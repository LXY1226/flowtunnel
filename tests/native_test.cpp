#include <exception>
#include <iostream>
void
test_protocol();
void
test_packet();
void
test_stream();
int
main()
{
    try
    {
        test_protocol();
        test_packet();
        test_stream();
        std::cout << "Protocol, packet and stream tests passed\n";
        return 0;
    }
    catch (const std::exception &error)
    {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
