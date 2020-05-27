# TRENTOS-M Network Stack

## Dependencies

The TRENTOS-M  Network Stack uses PicoTCP

The Network stack can be used in two different ways, in a SERVER configuration 
(where the APP listens for an incoming connection) and a CLIENT configuration 
(where the APP can connect to a remote host).

The Network Stack is implemented as a CAmkES component and in order to use it 
you must instantiate at least one such component and additionally an interface 
file and a CAmkES component file must be created/configured. 

The reference implementation can be found in the test_network_api folder in 
tests.
 
## IP Configuration
           
The Network Stack takes its IP addresses from the Configuration Server, by 
looking in the STACK domain after the following keys ETH_ADDR_CLIENT, 
ETH_ADDR_SERVER, ETH_GATEWAY_ADDR and ETH_SUBNET_MASK.

If Configuration Server isn't used, DEV_ADDR, GATEWAY_ADDR and SUBNET_MASK 
should be passed with values as compile arguments in CMakeLists.txt for the 
Network Stack components.

    -DDEV_ADDR="1.1.1.1"

## Dependencies

The Network depends on a network interface driver, the configuration server 
and the system libraries.

## Network interface file

The CAmkES interface implementation can be found in the `if_OS_socket.camkes`
 file.
     
## CAmkES configuration file

In order to use the Stack, your component definition needs to include the
 following.

    component <COMPONENT_NAME> {
        //Reference to the RPC socket interface
        uses      if_OS_socket    network_stack_rpc;
        //A buffer to send data to/from the stack
        dataport  Buf             buffer;
        //Event received when the stack is ready to be used
        consumes  ServiceReady    event_init_done;
    }

 
## CMakeLists.txt file

The component muth be build with one of the 2 `OS_NWSTACK_AS` defines. 

Define                            | Description
----------------------------------|---------------------------------------------------------------------------
OS_NWSTACK_AS_CLIENT              | use the Network stack as client (connect to remote host)
OS_NWSTACK_AS_SERVER              | use the Network stack as server (accept connection from remote host)
OS_NETWORK_STACK_USE_CONFIGSERVER | use configuration server to configure IP addresses

 
## Limitations
* Only IPv4 connections are supported
* Only TCP socket is supported
* Only 1 connection can be active at a given time
* Each APP needs its own Network Stack
* Network Stack needs to be specialized in Server/Client