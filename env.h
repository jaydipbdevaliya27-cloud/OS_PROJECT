#ifndef ENV_H
#define ENV_H

#define MAX_SHELL_VARS 100

struct ShellVar {
    char *name;
    char *value;
};

extern struct ShellVar shell_vars[MAX_SHELL_VARS];
extern int shell_var_count;

void init_shell_vars();
void update_shell_var(const char *name, const char *value, int i);
void create_shell_var(const char *name, const char *value);
void set_shell_var(const char *name, const char *value);
void print_shell_var();
int is_valid_assignment(const char* input);
void handle_valid_assignment(const char *input);
char* expand_variables(const char* input);

#endif