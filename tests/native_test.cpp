#include <exception>
#include <iostream>
void
test_protocol();
void
test_packet();
void
test_stream();
void
test_datagram_ack();
int
main()
{
    try
    {
        test_protocol();
        test_packet();
        test_stream();
        test_datagram_ack();
        std::cout << "Protocol, packet, stream and datagram ACK tests passed\n";
        return 0;
    }
    catch (const std::exception &error)
    {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
