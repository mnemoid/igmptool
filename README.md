# IGMPTOOL
Tool that acts as IGMP querier and IGMP packet logger. Can be started as a daemon or in interactive mode. 

## SYNOPSIS
    igmptool [-f] [-h] [-i <interface>] [-l <path>] [-L <level>] [-p <path>] [-q <interval>] [-r <interval>]

## OPTIONS
    -f      Don't fork (run in interactive mode).
    
    -h      Print help message.
    
    -i <interface>
            Specify network interface. Default: eth0.
            
    -l <path>
            Set log file path. Default: /var/log/igmptool/igmptool.log.
            
    -L <level>
            Log level from 0 (less information) to 7 (debug). Default: 5.
            
    -p <path>
            Set PID file path. Default: /var/run/igmptool.pid.
            
    -q <interval>
           Set general query interval in seconds. Default: 125 seconds.
           
    -r <interval>
           Set query response interval in 1/10th of second. Default: 10 seconds.
 
## BUILDING AND INSTALLATION
### Dependencies
* GCC compiler
* Cmake >= 3.0

### Building
For building igmptools, we need to create a separate build directory in project directory:

    mkdir build

After creating build directory `cd` into it and run `cmake`:

    cd build
    cmake ..

Once `cmake` generated makefile, we can build igmptool by running `make` inside our build directory:

    make

### Installation
When building is done, `igmptool` file appears in build directory. Now we can install igmptool daemon using `make install` command:

    make install
    
All done. You could use your own init script to control starting of igmptool daemon in system.
    
