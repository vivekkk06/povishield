#ifndef POVISHIELD_H
#define POVISHIELD_H

#define PS_VERSION "0.1.0"

/* subcommands: argv[0] is the subcommand name */
int cmd_run(int argc, char **argv);
int cmd_learn(int argc, char **argv);
int cmd_enforce(int argc, char **argv);
int cmd_info(int argc, char **argv);

/* helpers */
int ps_write_file(const char *path, const char *s);
int ps_total_syscalls(void);
/* Load a profile JSON and install a seccomp filter. audit=1 logs instead of killing. */
int ps_apply_seccomp(const char *profile, int audit);

int ps_validate_run_args(int argc, char **argv);   /* strict --mem/--pids/--cpu parsing */

#endif
