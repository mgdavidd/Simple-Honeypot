# Cargado vía --rcfile por logged-shell. Convierte cada comando que el
# atacante ejecuta en una línea de log, sin depender de HISTFILE en disco.

HISTFILE=/dev/null
HISTSIZE=1000
HISTCONTROL=

__honeypot_log_command() {
    local last
    last=$(HISTTIMEFORMAT= history 1 | sed 's/^ *[0-9]*  //')

    if [ -n "$last" ] && [ "$last" != "$HONEYPOT_LAST_LOGGED" ]; then
        export HONEYPOT_LAST_LOGGED="$last"
        printf 'CMD\t%s\t%s\t%s\t%s\n' \
            "$(date -Iseconds)" "$HONEYPOT_CLIENT_IP" "$HONEYPOT_CLIENT_PORT" "$last" \
            >> "$HONEYPOT_SESSION_FILE"
    fi
}

PROMPT_COMMAND="__honeypot_log_command"
PS1='\u@honeypot:\w\$ '

# Bloquear que el atacante termine el shell espía desde la sesión
if [ -n "${HONEYPOT_WRAPPER_PID:-}" ]; then
    kill() {
        local target="${@: -1}"
        if [ "$target" = "$HONEYPOT_WRAPPER_PID" ] || [ "$target" = "$PPID" ]; then
            echo "acces denied: cannot kill the bash process"
            return 1
        fi
        command kill "$@"
    }

    pkill() {
        echo "acces denied: cannot pkill from this session"
        return 1
    }

    killall() {
        echo "acces denied: cannot killall from this session"
        return 1
    }
fi