package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"multirepo-proxy/auth/basic"
	"multirepo-proxy/config"
	"multirepo-proxy/core"
	coredb "multirepo-proxy/core/db"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Start an MCP server (stdio) to manage multirepo-proxy via Claude",
	RunE:  runMCP,
}

func init() {
	rootCmd.AddCommand(mcpCmd)
}

func runMCP(_ *cobra.Command, _ []string) error {
	var cfg config.Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return fmt.Errorf("config: %w", err)
	}

	gdb, err := coredb.Open(cfg.Storage.DBPath)
	if err != nil {
		return fmt.Errorf("db: %w", err)
	}
	sqlDB, _ := gdb.DB()
	defer sqlDB.Close()

	quarantine := core.NewQuarantineStore(gdb)
	ruleStore  := core.NewRuleStore(gdb)
	groupStore := core.NewGroupStore(gdb)
	userStore  := basic.NewDBStore(gdb)

	s := server.NewMCPServer(
		"multirepo-proxy",
		"1.0.0",
		server.WithToolCapabilities(true),
	)

	// ── Quarantined packages ──────────────────────────────────────────────

	s.AddTool(mcp.NewTool("list_packages",
		mcp.WithDescription("List quarantined packages. Filter by status: pending, approved, rejected (default: all)."),
		mcp.WithString("status", mcp.Description("pending | approved | rejected | all"), mcp.DefaultString("all")),
		mcp.WithString("repo_type", mcp.Description("apt | docker | npm | pip | r | go — leave empty for all")),
	), func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()
		statusStr, _ := args["status"].(string)
		repoFilter, _ := args["repo_type"].(string)

		var statusPtr *core.Status
		if statusStr != "" && statusStr != "all" {
			s := core.Status(statusStr)
			statusPtr = &s
		}
		pkgs, err := quarantine.List(statusPtr)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		if repoFilter != "" {
			filtered := pkgs[:0]
			for _, p := range pkgs {
				if p.RepoType == repoFilter {
					filtered = append(filtered, p)
				}
			}
			pkgs = filtered
		}
		b, _ := json.MarshalIndent(pkgs, "", "  ")
		return mcp.NewToolResultText(string(b)), nil
	})

	s.AddTool(mcp.NewTool("get_package",
		mcp.WithDescription("Details of a package and its security report."),
		mcp.WithString("id", mcp.Required(), mcp.Description("UUID of the package")),
	), func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()
		id, _ := args["id"].(string)

		pkg, err := quarantine.Get(id)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		allFindings, _ := quarantine.GetAllFindings()
		result := map[string]any{
			"package":           pkg,
			"security_findings": allFindings[id],
		}
		b, _ := json.MarshalIndent(result, "", "  ")
		return mcp.NewToolResultText(string(b)), nil
	})

	s.AddTool(mcp.NewTool("approve_package",
		mcp.WithDescription("Approve a quarantined package."),
		mcp.WithString("id", mcp.Required(), mcp.Description("UUID of the package")),
		mcp.WithString("comment", mcp.Description("Optional comment")),
	), func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()
		id, _      := args["id"].(string)
		comment, _ := args["comment"].(string)
		if err := quarantine.Approve(id, "mcp", comment); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText("Package " + id + " approved."), nil
	})

	s.AddTool(mcp.NewTool("reject_package",
		mcp.WithDescription("Reject a quarantined package."),
		mcp.WithString("id", mcp.Required(), mcp.Description("UUID of the package")),
		mcp.WithString("comment", mcp.Description("Reason for rejection")),
	), func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()
		id, _      := args["id"].(string)
		comment, _ := args["comment"].(string)
		if err := quarantine.Reject(id, "mcp", comment); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText("Package " + id + " rejected."), nil
	})

	s.AddTool(mcp.NewTool("revoke_package",
		mcp.WithDescription("Revoke a package approval (puts it back to pending)."),
		mcp.WithString("id", mcp.Required(), mcp.Description("UUID of the package")),
		mcp.WithString("comment", mcp.Description("Reason for revocation")),
	), func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()
		id, _      := args["id"].(string)
		comment, _ := args["comment"].(string)
		if err := quarantine.Revoke(id, "mcp", comment); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText("Package " + id + " revoked."), nil
	})

	s.AddTool(mcp.NewTool("get_security_report",
		mcp.WithDescription("Returns vulnerabilities found for a package."),
		mcp.WithString("id", mcp.Required(), mcp.Description("UUID of the package")),
	), func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()
		id, _ := args["id"].(string)

		allFindings, err := quarantine.GetAllFindings()
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		findings := allFindings[id]
		if len(findings) == 0 {
			return mcp.NewToolResultText("No vulnerabilities found for this package."), nil
		}
		var sb strings.Builder
		for _, f := range findings {
			fmt.Fprintf(&sb, "[%s] %s — severity: %s, CVSS: %.1f, EPSS: %.3f\n  %s\n",
				f.Source, f.ID, f.Severity, f.CVSS, f.EPSS, f.Description)
		}
		return mcp.NewToolResultText(sb.String()), nil
	})

	s.AddTool(mcp.NewTool("stats",
		mcp.WithDescription("Summary: number of packages by status and repository type."),
	), func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		counts := map[string]int{}
		for _, st := range []core.Status{core.StatusPending, core.StatusApproved, core.StatusRejected} {
			stCopy := st
			pkgs, _ := quarantine.List(&stCopy)
			counts[string(st)] = len(pkgs)
		}
		b, _ := json.MarshalIndent(counts, "", "  ")
		return mcp.NewToolResultText(string(b)), nil
	})

	// ── Users ─────────────────────────────────────────────────────────────

	s.AddTool(mcp.NewTool("list_users",
		mcp.WithDescription("List all admin interface users."),
	), func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		users, err := userStore.ListUsers()
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		b, _ := json.MarshalIndent(users, "", "  ")
		return mcp.NewToolResultText(string(b)), nil
	})

	s.AddTool(mcp.NewTool("create_user",
		mcp.WithDescription("Create an admin user. Leave password empty for an anonymous account."),
		mcp.WithString("username", mcp.Required(), mcp.Description("Username")),
		mcp.WithString("password", mcp.Description("Password (empty = anonymous)")),
		mcp.WithString("groups", mcp.Description("Comma-separated groups, e.g.: admin,readers")),
	), func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()
		username, _ := args["username"].(string)
		password, _ := args["password"].(string)
		groupsStr, _ := args["groups"].(string)
		var groups []string
		if groupsStr != "" {
			groups = strings.Split(groupsStr, ",")
		}
		var err error
		if password == "" {
			err = userStore.AddUserAnonymous(username, groups...)
		} else {
			err = userStore.AddUser(username, password, groups...)
		}
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText("User " + username + " created."), nil
	})

	s.AddTool(mcp.NewTool("delete_user",
		mcp.WithDescription("Delete an admin user."),
		mcp.WithString("username", mcp.Required()),
	), func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()
		username, _ := args["username"].(string)
		if err := userStore.RemoveUser(username); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText("User " + username + " deleted."), nil
	})

	s.AddTool(mcp.NewTool("set_password",
		mcp.WithDescription("Change a user's password."),
		mcp.WithString("username", mcp.Required()),
		mcp.WithString("password", mcp.Required()),
	), func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()
		username, _ := args["username"].(string)
		password, _ := args["password"].(string)
		if err := userStore.AddUser(username, password); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText("Password for " + username + " updated."), nil
	})

	// ── Groups ────────────────────────────────────────────────────────────

	s.AddTool(mcp.NewTool("list_groups",
		mcp.WithDescription("List groups and their permissions."),
	), func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		groups, err := groupStore.List()
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		b, _ := json.MarshalIndent(groups, "", "  ")
		return mcp.NewToolResultText(string(b)), nil
	})

	// ── Auto-approval rules ───────────────────────────────────────────────

	s.AddTool(mcp.NewTool("list_rules",
		mcp.WithDescription("List auto-approval rules."),
	), func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		rules, err := ruleStore.List()
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		b, _ := json.MarshalIndent(rules, "", "  ")
		return mcp.NewToolResultText(string(b)), nil
	})

	s.AddTool(mcp.NewTool("set_rule_enabled",
		mcp.WithDescription("Enable or disable an auto-approval rule."),
		mcp.WithNumber("id", mcp.Required(), mcp.Description("Rule ID")),
		mcp.WithBoolean("enabled", mcp.Required(), mcp.Description("true = enabled, false = disabled")),
	), func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()
		idF, _     := args["id"].(float64)
		enabled, _ := args["enabled"].(bool)
		id := int(idF)

		rules, err := ruleStore.List()
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		for _, r := range rules {
			if r.ID == uint(id) {
				r.Enabled = enabled
				if err := ruleStore.Update(r); err != nil {
					return mcp.NewToolResultError(err.Error()), nil
				}
				state := "disabled"
				if enabled {
					state = "enabled"
				}
				return mcp.NewToolResultText(fmt.Sprintf("Rule %d %s.", id, state)), nil
			}
		}
		return mcp.NewToolResultError(fmt.Sprintf("Rule %d not found.", id)), nil
	})

	return server.NewStdioServer(s).Listen(context.Background(), nil, nil)
}
