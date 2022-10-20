package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	vault "github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/approle"
)

var envFile = flag.String("e", ".env", "PATH to .env file")
var appRolePath = flag.String("a", "approle", "Vault path to App Role mount")
var appRoleId = flag.String("r", "", "App Role Role ID")
var appRoleSecretId = flag.String("s", "", "App Role Secret ID")
var vaultAddr = flag.String("addr", "", "VAULT_ADDR")
var vaultNamespace = flag.String("namespace", "", "VAULT_NAMESPACE")

type reifier interface {
	// TODO: NO Idea yet.
	Reify(typ string, args ...interface{}) (interface{}, error)
}

type compoundReifier struct {
	rs map[string]reifier
}

func (r *compoundReifier) Reify(typ string, args ...interface{}) (interface{}, error) {
	x, ok := r.rs[typ]
	if !ok {
		return nil, errors.New("don't know how to reify things of that type")
	}
	return x.Reify(typ, args...)
}

type valuer interface {
	Eval(reifier) (string, error)
}

type entry struct {
	key   string
	value valuer
}

type constValue struct {
	value string
}

func (c constValue) Eval(_ reifier) (string, error) {
	return c.value, nil
}

type envValue struct {
	name string
}

func (e envValue) Eval(r reifier) (string, error) {
	x, err := r.Reify("env", e.name)
	if err != nil {
		return "", err
	}
	s, ok := x.(string)
	if !ok {
		return "", errors.New("unable to convert to string")
	}
	return s, nil
}

type compoundValue struct {
	values []valuer
}

func (c compoundValue) Eval(r reifier) (string, error) {
	var out bytes.Buffer
	for _, p := range c.values {
		bit, err := p.Eval(r)
		if err != nil {
			return "", err
		}
		out.WriteString(bit)
	}
	return out.String(), nil
}

type vaultValue struct {
	path     string
	selector string
}

func (v vaultValue) Eval(r reifier) (string, error) {
	out, err := r.Reify("vault", v.path)
	if err != nil {
		return "", err
	}

	cur, ok := out.(map[string]interface{})
	if !ok {
		return "", errors.New("unable to assert as map")
	}

	if v.selector != "" {
		paths := strings.Split(v.selector, ".")
		for _, p := range paths[0 : len(paths)-1] {
			cur, ok = cur[p].(map[string]interface{})
			if !ok {
				return "", fmt.Errorf("key not found while traversing: %s", v.selector)
			}
		}

		last := paths[len(paths)-1]
		vhope, ok := cur[last]
		if !ok {
			return "", fmt.Errorf("key not found: %s", v.selector)
		}
		return fmt.Sprintf("%s", vhope), nil
	}

	return fmt.Sprintf("%s", cur), err
}

type envReifier struct {
	// nothing needed.
}

func (e envReifier) Reify(_ string, args ...interface{}) (interface{}, error) {
	if len(args) != 1 {
		return "", errors.New("must provide a string to reify")
	}
	s, ok := args[0].(string)
	if !ok {
		return "", errors.New("must provide string to reify")
	}
	return os.Getenv(s), nil
}

type vaultReifier struct {
	responses map[string]interface{}
	client    *vault.Client
}

func (e *vaultReifier) Reify(_ string, args ...interface{}) (interface{}, error) {
	if len(args) != 1 {
		return "", errors.New("must provide a string to reify")
	}
	s, ok := args[0].(string)
	if !ok {
		return "", errors.New("must provide a path to reify")
	}

	if v, ok := e.responses[s]; ok {
		return v, nil
	}

	// wasn't cached, find it.
	req := e.client.NewRequest(http.MethodGet, s)
	resp, err := e.client.RawRequest(req)
	if err != nil {
		return nil, fmt.Errorf("unable to create raw request: %w", err)
	}

	v := make(map[string]interface{})
	err = resp.DecodeJSON(&v)
	if err != nil {
		return nil, fmt.Errorf("unable to decode json response: %w", err)
	}

	e.responses[s] = v
	return v, nil
}

func defaultenv(set *string, env string) string {
	if *set == "" {
		*set = os.Getenv(env)
	}
	return *set
}

func vaultClient() (*vault.Client, error) {

	if defaultenv(appRolePath, "APPROLE_ROLE_PATH") == "" {
		return nil, errors.New("No approle path found")
	}

	if defaultenv(appRoleId, "APPROLE_ROLE_ID") == "" {
		return nil, errors.New("No approle role id provided")
	}

	if defaultenv(appRoleSecretId, "APPROLE_SECRET_ID") == "" {
		return nil, errors.New("No approle secret id provided")
	}

	if defaultenv(vaultAddr, "VAULT_ADDR") == "" {
		return nil, errors.New("No VAULT_ADDR provided")
	}

	if defaultenv(vaultNamespace, "VAULT_NAMESPACE") == "" {
		*vaultNamespace = ""
	}

	config := vault.DefaultConfig() // modify for more granular configuration
	config.Address = *vaultAddr
	client, err := vault.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize Vault client: %w", err)
	}
	if *vaultNamespace != "" {
		client.WithNamespace(*vaultNamespace)
	}

	secretId := &auth.SecretID{FromString: *appRoleSecretId}
	appRoleAuth, err := auth.NewAppRoleAuth(
		*appRoleId,
		secretId,
		auth.WithMountPath(*appRolePath),
	)

	if err != nil {
		return nil, fmt.Errorf("unable to initialize AppRole auth method: %w", err)
	}

	authInfo, err := client.Auth().Login(context.Background(), appRoleAuth)
	if err != nil {
		return nil, fmt.Errorf("unable to login to AppRole auth method: %w", err)
	}
	if authInfo == nil {
		return nil, fmt.Errorf("no auth info was returned after login")
	}

	// otherwise, login, and return a client with token.
	return client, nil
}

// Here's the magic. We've gotta parse things.
func valueToValuer(v string) (valuer, error) {
	var valuers []valuer
	bits := strings.Split(v, "${")
	if len(bits) == 1 {
		return constValue{v}, nil
	}

	for _, b := range bits {
		if b == "" {
			continue
		}

		close := strings.Index(b, "}")
		if close >= 0 {
			v = b[0:close]

			if v != "" {
				// found a thing. Assume env for now
				if strings.HasPrefix(v, "vault://") {
					vbits := strings.SplitN(strings.TrimPrefix(v, "vault://"), "#", 2)
					if len(vbits) > 1 {
						valuers = append(valuers, vaultValue{
							path:     vbits[0],
							selector: vbits[1],
						})
					} else {
						valuers = append(valuers, vaultValue{
							path: vbits[0],
						})
					}
				} else {
					valuers = append(valuers, envValue{v})
				}
			}
		}

		rest := b[close+1 : len(b)]
		if rest != "" {
			valuers = append(valuers, constValue{rest})
		}
	}

	switch len(valuers) {
	case 1:
		return valuers[0], nil
	case 0:
		return constValue{""}, nil
	default:
		return compoundValue{valuers}, nil
	}
}

// parseEnv returns a struct that will be walked for generation purposes.
func parseEnv(f io.Reader) ([]entry, error) {
	var entries []entry
	var name string
	var value string

	scanner := bufio.NewScanner(f) // lines
	for scanner.Scan() {
		if name == "" { /* we don't have a name yet. */
			bits := strings.SplitN(scanner.Text(), "=", 2)

			if strings.Index(bits[0], "\t ") >= 0 {
				return nil, fmt.Errorf("invalid name: %q", bits[0])
			}
			/* alright, no spaces, assume we're good */
			name = bits[0]

			v := strings.TrimLeft(strings.TrimRight(bits[1], "\t "), "\t ")
			/* if the value is quoted, we might have multiple lines to worry
			   about */
			if strings.HasPrefix(v, "\"") {
				/* is the end of the string on this line? */
				if strings.HasSuffix(v, "\"") && !strings.HasSuffix(v, "\\\"") {
					/* and now we're done */
					value = v

					/* strip quotes. */
					value = strings.TrimRight(strings.TrimLeft(value, "\""), "\"")

					ver, err := valueToValuer(value)
					if err != nil {
						return nil, err
					}

					entries = append(entries, entry{key: name, value: ver})
					name = ""
					value = ""
					continue
				}

				/* not the end of the string. let's add on */
				value = v
			} else {
				/* no quotes, so we have the full thing */
				ver, err := valueToValuer(v)
				if err != nil {
					return nil, err
				}

				entries = append(entries, entry{key: name, value: ver})
				name = ""
				value = ""
				continue
			}
		} else {
			/* we're continuing, and need a closing quote */
			v := strings.TrimRight(scanner.Text(), "\t ")
			if strings.HasSuffix(v, "\"") {
				/* ok, we're done. */
				if value != "" {
					value = value + "\n" + v
				} else {
					value = v
				}
				value = strings.TrimRight(strings.TrimLeft(value, "\""), "\"")
				ver, err := valueToValuer(value)
				if err != nil {
					return nil, err
				}

				entries = append(entries, entry{key: name, value: ver})
				name = ""
				value = ""
				continue
			} else {
				value = value + "\n" + v
			}
		}
	}

	if name != "" {
		return nil, fmt.Errorf("incomplete value for %q", name)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return entries, nil
}

func testParseEnv(f io.Reader) ([]entry, error) {
	return []entry{
		{"HOME", &envValue{"HOME"}},
		{"PATH", &constValue{"/bin:/usr/bin"}},
		{"COMPLEX", compoundValue{
			values: []valuer{
				&constValue{value: "HELLO "},
				&envValue{name: "USER"},
			},
		}},
	}, nil
}

func reifyEnv(r reifier, es []entry) ([]string, error) {
	var out []string
	for _, e := range es {
		v, err := e.value.Eval(r)
		if err != nil {
			return nil, err
		}
		ev := fmt.Sprintf("%s=%s", e.key, v)
		out = append(out, ev)
	}

	return out, nil
}

func forwardSignals(cmd *exec.Cmd) {
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc)
	go func() {
		for {
			s := <-sigc
			cmd.Process.Signal(s)
		}
	}()
}

func run(c []string, env []string) {
	if len(c) == 0 {
		os.Exit(0)
	}

	cmd := exec.Command(c[0], c[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: fatal: failed to run command: %s\n", c[0], err)
		os.Exit(1)
	}

	forwardSignals(cmd)

	err = cmd.Wait()
	if err == nil {
		os.Exit(0) // Successful.
	} else if exit, ok := err.(*exec.ExitError); ok {
		if s, ok := exit.Sys().(syscall.WaitStatus); ok {
			os.Exit(s.ExitStatus())
		}
	}

	fmt.Fprintf(os.Stderr, "%s: fatal: failed to run command: %s\n", os.Args[0], err)
	os.Exit(1)
}

func main() {
	flag.Parse()

	f, err := os.Open(*envFile)
	if err != nil {
		panic(err)
	}

	entries, err := parseEnv(f)
	if err != nil {
		panic(err)
	}

	// Cool. Start the Reification process
	client, err := vaultClient()
	if err != nil {
		panic(err)
	}

	r := &compoundReifier{
		rs: map[string]reifier{
			"env": &envReifier{},
			"vault": &vaultReifier{
				client:    client,
				responses: make(map[string]interface{}),
			},
		},
	}

	newEnv, err := reifyEnv(r, entries)
	if err != nil {
		panic(err)
	}

	run(flag.Args(), newEnv)
}
