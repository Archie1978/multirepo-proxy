package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"

	"multirepo-proxy/auth/basic"
	coredb "multirepo-proxy/core/db"
)

func init() {
	userAddCmd.Flags().StringVar(&addGroups, "groups", "admin", "comma-separated groups (e.g.: admin,ops)")
	userCmd.AddCommand(userAddCmd, userRemoveCmd, userListCmd, userPasswdCmd)
	rootCmd.AddCommand(userCmd)
}

var userCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage users (groups, passwords)",
	Long: `User management commands for accounts stored in the SQLite auth database.
These users are used regardless of the provider (basic, ldap, oidc):
  - basic  : password verification + groups
  - ldap / oidc : local groups only (password is ignored)

The database is read from auth.db_path if set, otherwise from storage.db_path.`,
}

var addGroups string

var userAddCmd = &cobra.Command{
	Use:   "add <username>",
	Short: "Add or update a user",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		store, closeDB, err := openUserStore()
		if err != nil {
			return err
		}
		defer closeDB()

		password, err := promptPassword("Password: ")
		if err != nil {
			return err
		}
		confirm, err := promptPassword("Confirm: ")
		if err != nil {
			return err
		}
		if password != confirm {
			return fmt.Errorf("passwords do not match")
		}

		var groups []string
		if addGroups != "" {
			for _, g := range strings.Split(addGroups, ",") {
				if g = strings.TrimSpace(g); g != "" {
					groups = append(groups, g)
				}
			}
		}
		if err := store.AddUser(args[0], password, groups...); err != nil {
			return err
		}
		if len(groups) > 0 {
			fmt.Printf("User %q added (groups: %s).\n", args[0], strings.Join(groups, ", "))
		} else {
			fmt.Printf("User %q added.\n", args[0])
		}
		return nil
	},
}

var userRemoveCmd = &cobra.Command{
	Use:   "remove <username>",
	Short: "Remove a user",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		store, closeDB, err := openUserStore()
		if err != nil {
			return err
		}
		defer closeDB()

		if err := store.RemoveUser(args[0]); err != nil {
			return err
		}
		fmt.Printf("User %q removed.\n", args[0])
		return nil
	},
}

var userListCmd = &cobra.Command{
	Use:   "list",
	Short: "List users",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		store, closeDB, err := openUserStore()
		if err != nil {
			return err
		}
		defer closeDB()

		users, err := store.ListUsers()
		if err != nil {
			return err
		}
		if len(users) == 0 {
			fmt.Println("No users.")
			return nil
		}
		fmt.Printf("%-24s  %s\n", "USERNAME", "GROUPS")
		for _, u := range users {
			fmt.Printf("%-24s  %s\n", u.Username, strings.Join(u.Groups, ", "))
		}
		return nil
	},
}

var userPasswdCmd = &cobra.Command{
	Use:   "passwd <username>",
	Short: "Change a user's password",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		store, closeDB, err := openUserStore()
		if err != nil {
			return err
		}
		defer closeDB()

		password, err := promptPassword("New password: ")
		if err != nil {
			return err
		}
		confirm, err := promptPassword("Confirm: ")
		if err != nil {
			return err
		}
		if password != confirm {
			return fmt.Errorf("passwords do not match")
		}
		if err := store.AddUser(args[0], password); err != nil {
			return err
		}
		fmt.Printf("Password for %q updated.\n", args[0])
		return nil
	},
}

// openUserStore opens the auth database and returns a DBStore + a close function.
// Priority: auth.db_path → storage.db_path.
func openUserStore() (*basic.DBStore, func(), error) {
	dbPath := viper.GetString("auth.db_path")
	if dbPath == "" {
		dbPath = viper.GetString("storage.db_path")
	}
	if dbPath == "" {
		return nil, nil, fmt.Errorf("auth.db_path or storage.db_path not configured")
	}
	gdb, err := coredb.OpenAuth(dbPath)
	if err != nil {
		return nil, nil, fmt.Errorf("db: %w", err)
	}
	sqlDB, _ := gdb.DB()
	return basic.NewDBStore(gdb), func() { sqlDB.Close() }, nil
}

// promptPassword reads a password without echo on the terminal.
func promptPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	raw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println() // newline after masked input
	if err != nil {
		return "", fmt.Errorf("reading password: %w", err)
	}
	if len(raw) == 0 {
		return "", fmt.Errorf("password cannot be empty")
	}
	return string(raw), nil
}
