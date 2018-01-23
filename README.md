# tstime

This project is adapted from [gsauthof/tstime](https://bitbucket.org/gsauthof/tstime/).

It is used to run a command with certain limits (time, RSS/VM usage, file size, system call, processes, CPU set) and collect its accounting information provided by taskstats.

## Usage

    ./tstime UID [options] COMMAND [args]

Run COMMAND by user UID. `UID=0` is not allowed.

It will output 16 lines:

    24299       # PID
    1516714564  # start time
    0           # exit code
    16000000    # CPU real running time (nsec)
    13447843    # CPU virtual running time (nsec)
    12000       # User CPU time (usec)
    4000        # System CPU time (usec)
    16495       # Wall clock time (usec)
    1116        # High-water VM usage (KB)
    684         # High-water RSS usage (KB)
    17437       # Accumulated VM usage (MB-usec)
    62          # Accumulated RSS usage (MB-usec)
    0           # Bytes read
    1048576     # Bytes written
    0           # Bytes of read I/O
    1048576     # Bytes of write I/O

