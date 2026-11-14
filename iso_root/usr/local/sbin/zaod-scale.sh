#!/bin/sh
set -u

MODE_DIR=/run/zaod-scale
CPU_ROOT=/sys/devices/system/cpu

log()
{
    if command -v logger >/dev/null 2>&1; then
        logger -t zaod-scale "$*"
    else
        printf '%s\n' "zaod-scale: $*" >&2
    fi
}

if [ "$(id -u)" -ne 0 ]; then
    log "ERROR: run this script as root to apply CPU and I/O policies"
    exit 1
fi

ram_kib=$(awk '$1 == "MemTotal:" { print $2; exit }' /proc/meminfo)
case "$ram_kib" in
    ''|*[!0-9]*)
        log "ERROR: could not read total RAM from /proc/meminfo"
        exit 1
        ;;
esac

cpu_cores=$(awk '/^processor[[:space:]]*:/ { count++ } END { print count+0 }' /proc/cpuinfo)
if [ "$cpu_cores" -lt 1 ]; then
    cpu_cores=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1\n')
fi
case "$cpu_cores" in
    ''|*[!0-9]*) cpu_cores=1 ;;
esac

if grep -qi 'Celeron' /proc/cpuinfo || [ "$ram_kib" -lt 3145728 ]; then
    mode=lite
elif [ "$ram_kib" -ge 4194304 ] && [ "$cpu_cores" -ge 2 ]; then
    mode=pro
else
    mode=lite
fi

if ! mkdir -p "$MODE_DIR" || ! printf '%s\n' "$mode" > "$MODE_DIR/mode"; then
    log "ERROR: could not publish selected mode at $MODE_DIR/mode"
    exit 1
fi

set_cpu_governor()
{
    requested=$1
    applied=0

    for governor_file in "$CPU_ROOT"/cpu[0-9]*/cpufreq/scaling_governor; do
        [ -w "$governor_file" ] || continue
        available_file=${governor_file%scaling_governor}scaling_available_governors

        if [ "$requested" = lite ]; then
            for candidate in schedutil powersave; do
                if [ -r "$available_file" ] &&
                    ! grep -qw "$candidate" "$available_file"; then
                    continue
                fi
                if printf '%s\n' "$candidate" > "$governor_file"; then
                    applied=$((applied + 1))
                    break
                fi
                log "WARNING: could not set $governor_file to $candidate"
            done
        else
            if printf '%s\n' performance > "$governor_file"; then
                applied=$((applied + 1))
            else
                log "WARNING: could not set $governor_file to performance"
            fi
        fi
    done

    if [ "$applied" -eq 0 ]; then
        log "WARNING: no writable CPU frequency governor was found"
    else
        log "applied CPU governor policy to $applied CPU entries"
    fi
}

set_io_scheduler()
{
    applied=0

    for scheduler_file in /sys/block/*/queue/scheduler; do
        [ -r "$scheduler_file" ] && [ -w "$scheduler_file" ] || continue
        schedulers=$(cat "$scheduler_file")
        case " $schedulers " in
            *" mq-deadline "*|*" [mq-deadline] "*)
                if printf '%s\n' mq-deadline > "$scheduler_file"; then
                    applied=$((applied + 1))
                else
                    log "WARNING: could not set I/O scheduler at $scheduler_file"
                fi
                ;;
        esac
    done

    if [ "$applied" -eq 0 ]; then
        log "WARNING: mq-deadline is unavailable on detected block devices"
    else
        log "selected mq-deadline on $applied block devices"
    fi
}

apply_session_policy()
{
    if [ -n "${HYPRLAND_INSTANCE_SIGNATURE:-}" ] &&
        command -v hyprctl >/dev/null 2>&1; then
        if [ "$mode" = lite ]; then
            hyprctl keyword animations:enabled false >/dev/null ||
                log "WARNING: could not disable Hyprland animations"
            hyprctl keyword decoration:blur:enabled false >/dev/null ||
                log "WARNING: could not disable Hyprland blur"
        else
            hyprctl keyword animations:enabled true >/dev/null ||
                log "WARNING: could not enable Hyprland animations"
        fi
    else
        log "no active Hyprland control session; compositor policy is $mode"
    fi
}

if [ "$mode" = lite ]; then
    set_cpu_governor lite
else
    set_cpu_governor pro
fi
set_io_scheduler
apply_session_policy

log "selected $mode mode (RAM ${ram_kib} KiB, $cpu_cores CPU cores)"
