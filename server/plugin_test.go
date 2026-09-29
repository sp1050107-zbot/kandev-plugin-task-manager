package main

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/kandev/kandev/pkg/pluginsdk"
)

// The UI polls with POST rather than GET. Kandev rejects a
// session-authenticated webhook call that carries no Origin header (CSRF
// protection), and browsers omit Origin on same-origin GETs — so a GET poll
// is answered 403 by the host on any instance with authentication enabled,
// and the panel renders as though nothing were running. Accepting POST is
// what keeps the UI working there.
func TestHandleWebhookAcceptsTheMethodsTheUIAndCLIUse(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodGet, ""} {
		t.Run("method="+method, func(t *testing.T) {
			p := newPlugin()
			resp, err := p.HandleWebhook(context.Background(), &pluginsdk.WebhookRequest{
				WebhookKey: "usage",
				Method:     method,
			})
			if err != nil {
				t.Fatalf("HandleWebhook: %v", err)
			}
			if resp.Status != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body: %s)", resp.Status, resp.Body)
			}
			var body map[string]any
			if err := json.Unmarshal(resp.Body, &body); err != nil {
				t.Fatalf("response is not JSON: %v", err)
			}
			if _, ok := body["supported"]; !ok {
				t.Errorf("response missing 'supported': %s", resp.Body)
			}
		})
	}
}

func TestHandleWebhookRefusesOtherMethods(t *testing.T) {
	p := newPlugin()
	resp, err := p.HandleWebhook(context.Background(), &pluginsdk.WebhookRequest{
		WebhookKey: "usage",
		Method:     http.MethodDelete,
	})
	if err != nil {
		t.Fatalf("HandleWebhook: %v", err)
	}
	if resp.Status != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.Status)
	}
}

func TestHandleWebhookRejectsAnUnknownKey(t *testing.T) {
	p := newPlugin()
	resp, err := p.HandleWebhook(context.Background(), &pluginsdk.WebhookRequest{
		WebhookKey: "not-a-key",
		Method:     http.MethodPost,
	})
	if err != nil {
		t.Fatalf("HandleWebhook: %v", err)
	}
	if resp.Status != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.Status)
	}
}

// configHost is a minimal Host that serves only GetConfig; every data reader
// comes from UnimplementedHostData (title lookups fail soft and are ignored).
type configHost struct {
	pluginsdk.UnimplementedHostData
	config map[string]any
	err    error
}

func (h *configHost) GetState(context.Context, string, string, string) (map[string]any, bool, error) {
	return nil, false, nil
}
func (h *configHost) SetState(context.Context, string, string, string, map[string]any) error {
	return nil
}
func (h *configHost) DeleteState(context.Context, string, string, string) error { return nil }
func (h *configHost) ListState(context.Context, string, string) ([]pluginsdk.StateEntry, error) {
	return nil, nil
}
func (h *configHost) GetConfig(context.Context) (map[string]any, error) {
	if h.err != nil {
		return nil, h.err
	}
	if h.config == nil {
		return map[string]any{}, nil
	}
	return h.config, nil
}
func (h *configHost) RevealSecret(context.Context, string) (string, error) { return "", nil }
func (h *configHost) GetSecret(context.Context, string) (string, bool, error) {
	return "", false, nil
}
func (h *configHost) SetSecret(context.Context, string, string) error         { return nil }
func (h *configHost) DeleteSecret(context.Context, string) error              { return nil }
func (h *configHost) EmitEvent(context.Context, string, map[string]any) error { return nil }

// newCommandTestPlugin wires the plugin to a fake process table holding one
// attributed process whose command line is set.
func newCommandTestPlugin(host pluginsdk.Host) *taskManagerPlugin {
	agent := proc(10, 1, "claude", 1, 1<<20)
	agent.Command = "claude --model opus"
	scanner := &fakeScanner{
		tables: [][]procSample{{agent}},
		env:    map[int]identity{10: {taskID: "task-a", sessionID: "s1"}},
	}
	s, _ := newTestSampler(scanner)
	p := &taskManagerPlugin{sampler: s, titles: newTitleCache()}
	if host != nil {
		p.SetHost(host)
	}
	return p
}

func commandsIn(t *testing.T, resp *pluginsdk.WebhookResponse) []string {
	t.Helper()
	var body snapshot
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if len(body.Tasks) == 0 {
		t.Fatalf("no tasks in response: %s", resp.Body)
	}
	var out []string
	for _, task := range body.Tasks {
		for _, p := range task.Processes {
			out = append(out, p.Command)
		}
	}
	return out
}

func TestShowCommandsSetting(t *testing.T) {
	cases := []struct {
		name string
		host pluginsdk.Host
		want string
	}{
		{"no host yet", nil, "claude --model opus"},
		{"unset defaults to shown", &configHost{}, "claude --model opus"},
		{"explicit true", &configHost{config: map[string]any{"show_commands": true}}, "claude --model opus"},
		{"explicit false hides", &configHost{config: map[string]any{"show_commands": false}}, ""},
		{"non-bool ignored", &configHost{config: map[string]any{"show_commands": "nope"}}, "claude --model opus"},
		{"config error keeps default", &configHost{err: errScanFailed}, "claude --model opus"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newCommandTestPlugin(tc.host)
			resp, err := p.HandleWebhook(context.Background(), &pluginsdk.WebhookRequest{
				WebhookKey: "usage",
				Method:     http.MethodPost,
			})
			if err != nil {
				t.Fatalf("HandleWebhook: %v", err)
			}
			for _, got := range commandsIn(t, resp) {
				if got != tc.want {
					t.Errorf("command = %q, want %q", got, tc.want)
				}
			}
		})
	}
}
