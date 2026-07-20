# Program one or more Alveo cards with the graph-plugin bitfile via JTAG.
# Driven by program_fpga.sh via environment variables:
#   BITFILE     path to the .bit to load
#   HW_TARGETS  space/newline-separated hw_target URLs to program
#   HW_LIST     if "1", just enumerate the JTAG targets and exit (program nothing)
#
# octo250 has 8 U250s on one JTAG chain, each its own hw_target, so a bare
# `open_hw_target` is ambiguous — targets are always named explicitly here.

open_hw_manager
connect_hw_server -url localhost:3121

# --- list mode: show every target/device, then quit ---
if {[info exists env(HW_LIST)] && $env(HW_LIST) eq "1"} {
    puts "=== Available JTAG targets ==="
    foreach t [get_hw_targets] {
        open_hw_target $t
        foreach d [get_hw_devices] { puts "  $t  ->  $d" }
        close_hw_target
    }
    disconnect_hw_server
    exit
}

# --- program mode ---
if {![info exists env(BITFILE)]} {
    puts "ERROR: BITFILE not set"
    exit 1
}
set bitfile $env(BITFILE)

if {[info exists env(HW_TARGETS)] && [string trim $env(HW_TARGETS)] ne ""} {
    set targets [regexp -all -inline {\S+} $env(HW_TARGETS)]
} else {
    # backward compatibility: single card on the chain
    set targets [list [lindex [get_hw_targets] 0]]
}

foreach t $targets {
    puts "=== Programming $t ==="
    open_hw_target $t
    set dev [lindex [get_hw_devices] 0]
    current_hw_device $dev
    set_property PROGRAM.FILE $bitfile $dev
    program_hw_devices $dev
    close_hw_target
    puts "=== Done $t ==="
}

disconnect_hw_server
exit
