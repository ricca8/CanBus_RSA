#include "./include/socketcan_cpp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/can/raw.h>


namespace scpp{

    SocketCan::SocketCan(){}

    SocketCanStatus SocketCan::open(const std::string & can_interface, int read_timeout_ms, SocketMode mode){
        m_interface = can_interface;
        m_socket_mode = mode;
        m_read_timeout_ms = read_timeout_ms;

        //Opening socket
        if ((m_socket = socket(PF_CAN, SOCK_RAW, CAN_RAW)) < 0){
            perror("socket");
            return STATUS_SOCKET_CREATE_ERROR;
        }
        int mtu, enable_canfd = 1;
        struct sockaddr_can addr;
        struct ifreq ifr;

        strncpy(ifr.ifr_name, can_interface.c_str(), IFNAMSIZ - 1);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';
        ifr.ifr_ifindex = if_nametoindex(ifr.ifr_name);
        if (!ifr.ifr_ifindex) {
            perror("if_nametoindex");
            return STATUS_INTERFACE_NAME_TO_IDX_ERROR;
        }

        addr.can_family = AF_CAN;
        addr.can_ifindex = ifr.ifr_ifindex;

        if (mode == MODE_CANFD_MTU)
        {
            //Check if the frame fits into the CAN
            if (ioctl(m_socket, SIOCGIFMTU, &ifr) < 0) {
                perror("SIOCGIFMTU");
                return STATUS_MTU_ERROR;
            }
            mtu = ifr.ifr_mtu;

            if (mtu != CANFD_MTU) {
                return STATUS_CANFD_NOT_SUPPORTED;
            }

            //Interface is ok - try to switch the socket into CAN FD mode
            if (setsockopt(m_socket, SOL_CAN_RAW, CAN_RAW_FD_FRAMES, &enable_canfd, sizeof(enable_canfd))){
                return STATUS_ENABLE_FD_SUPPORT_ERROR;
            }
        }


        struct timeval tv;
        //100 seconds timeout for each read. When a frame is received, timeout is not considered
        tv.tv_sec = 100;
        tv.tv_usec = m_read_timeout_ms * 100;
        setsockopt(m_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv,sizeof(struct timeval));

        if (bind(m_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("bind");
            return STATUS_BIND_ERROR;
        }

        return STATUS_OK;
    }


    SocketCanStatus SocketCan::write(const CanFrame & msg){

        struct canfd_frame frame;

        //Init CAN FD frame
        memset(&frame, 0, sizeof(frame));

        frame.can_id = msg.id;
        frame.len = msg.len;
        frame.flags = msg.flags;
        memcpy(frame.data, msg.data, msg.len);


        //Send frame
        if (::write(m_socket, &frame, sizeof(frame))) {
            return STATUS_WRITE_ERROR;
        }
        return STATUS_OK;
    }


    SocketCanStatus SocketCan::read(CanFrame & msg){
        struct canfd_frame frame;

        //Read a CAN frame
        long num_bytes = ::read(m_socket, &frame, sizeof(frame));

        if (num_bytes < sizeof(frame))
            printf("Error reading\n");


        msg.id = frame.can_id;
        msg.len = frame.len;
        msg.flags = frame.flags;
        memcpy(msg.data, frame.data, frame.len);

        return STATUS_OK;
    }


    SocketCanStatus SocketCan::close(){

        ::close(m_socket);
        return STATUS_OK;
    }


    const std::string & SocketCan::interfaceName() const{
        return m_interface;
    }


    SocketCan::~SocketCan(){
        close();
    }
}
