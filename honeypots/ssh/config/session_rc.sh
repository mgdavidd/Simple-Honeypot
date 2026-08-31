# Configuración de sesión interactiva del sistema.

HISTFILE=/dev/null
HISTSIZE=1000
HISTCONTROL=

# log de comandos
__sys_log_cmd() {
    local _last
    _last=$(HISTTIMEFORMAT= history 1 | sed 's/^ *[0-9]*  //')
    if [ -n "$_last" ] && [ "$_last" != "$_SYS_LAST_CMD" ]; then
        export _SYS_LAST_CMD="$_last"
        printf 'CMD\t%s\t%s\t%s\t%s\n' \
            "$(date -Iseconds)" "$_CLIENT_IP" "$_CLIENT_PORT" "$_last" \
            >> "$_SESSION_FILE" 2>/dev/null
    fi
}
PROMPT_COMMAND="__sys_log_cmd"
export PROMPT_COMMAND
# BASH_ENV hace que subshells no-interactivos también carguen este rc
export BASH_ENV=/etc/ssh/session.rc

# Prompt
if [ -n "$TERM" ] && [ "$TERM" != "dumb" ]; then
    RED='\[\e[31m\]'
    GREEN='\[\e[32m\]'
    YELLOW='\[\e[33m\]'
    CYAN='\[\e[36m\]'
    BOLD='\[\e[1m\]'
    RESET='\[\e[0m\]'
else
    RED=''
    GREEN=''
    YELLOW=''
    CYAN=''
    BOLD=''
    RESET=''
fi

PS1="${BOLD}${GREEN}\u${RESET}@${CYAN}${HOSTNAME_OVERRIDE:-ubuntu-server}${RESET}:${YELLOW}\w${RESET}\\$ "

# Protección de shell
if [ -n "${_SYS_SHELL_PID:-}" ]; then
    kill() {
        local _target="${@: -1}"
        if [ "$_target" = "$_SYS_SHELL_PID" ] || [ "$_target" = "$PPID" ]; then
            echo "bash: kill: ($_target) - Operation not permitted"
            return 1
        fi
        command kill "$@"
    }
    pkill()   { echo "bash: pkill: Operation not permitted";   return 1; }
    killall() { echo "bash: killall: Operation not permitted"; return 1; }
fi

# Se definen como funciones shell: se heredan a subshells vía export -f,
# y el atacante no puede saltarlas con "command bash" desde esta sesión.
for _s in bash sh dash zsh fish python python3 perl ruby; do
    if command -v "$_s" &>/dev/null; then
        eval "
${_s}() {
    printf 'CMD\t%s\t%s\t%s\tshell:${_s} %s\n' \
        \"\$(date -Iseconds)\" \"\${_CLIENT_IP:-}\" \"\${_CLIENT_PORT:-}\" \"\$*\" \
        >> \"\${_SESSION_FILE:-/dev/null}\" 2>/dev/null
    echo \"bash: ${_s}: restricted: cannot execute\" >&2
    return 1
}
export -f ${_s}
"
    fi
done
unset _s