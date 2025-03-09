#include <iostream>
#include <fstream>
#include <string>
#include <exception>
#include <filesystem>
#include <stdexcept>
#include <array>
#include <span>
#include <optional>

#include <sodium.h>
#include <nlohmann/json.hpp>


#ifdef _WIN32

    #include <winsock2.h>
    #include <ws2tcpip.h>

    const std::string endline = "\n";

#else

    #include <arpa/inet.h>

    const std::string endline = "\n";

#endif


std::string base64( std::span<const uint8_t> data ) {

    const std::size_t length = sodium_base64_encoded_len( data.size(), sodium_base64_VARIANT_ORIGINAL );
    char* buffer = new char[length];
    sodium_bin2base64( buffer, length, data.data(), data.size(), sodium_base64_VARIANT_ORIGINAL );
    const std::string result( buffer );
    delete[] buffer;
    return result;

}


std::string stringify( const in_addr& address, std::optional<in_addr> mask = std::nullopt ) {

    std::string buffer;
    buffer.resize( INET_ADDRSTRLEN );

    inet_ntop( AF_INET, &address, buffer.data(), buffer.size() );

    buffer = buffer.c_str();

    if ( mask ) {

        uint32_t mask_int = ntohl( mask.value().S_un.S_addr );
        std::size_t i = 0;

        while ( mask_int ) {

            i += mask_int & 1;
            mask_int >>= 1;

        }

        buffer += "/" + std::to_string( i );

    }

    return buffer;

}


struct KeyPair {

    std::array<uint8_t, crypto_box_PUBLICKEYBYTES> public_key;
    std::array<uint8_t, crypto_box_SECRETKEYBYTES> private_key;

};


KeyPair generate_keypair() {

    KeyPair temp;

    if ( crypto_box_keypair( temp.public_key.data(), temp.private_key.data() ) != 0 ) throw std::runtime_error( "Błąd generowania pary kluczy" );

    return temp;

}


class Config {

    public:

        Config( const std::filesystem::path& json_file ) : 
            _server_keypair( generate_keypair() ) {

            std::ifstream file( json_file );

            const auto config = nlohmann::json::parse( file );

            _using_dns = config["dns"].get<bool>();
            _using_intranet = config["intranet"].get<bool>();

            _bind = config["bind"].get<uint16_t>();
            _endpoint = config["endpoint"].get<std::string>();
            _interface = config["interface"].get<std::string>();

            const auto peers = config["peers"];

            if ( !peers.is_array() || !( [&peers](){

                bool every = true;

                for ( const auto& item : peers ) every &= item.is_string();

                return every;

            } )() ) throw std::runtime_error( R"("Peers" must be a array of strings)" );
            else _peers = peers;

            const std::string network = config["network"].get<std::string>();
            const auto slash = network.find( '/' );

            _network.S_un.S_addr = inet_addr( network.substr( 0, slash ).c_str() );

            _next = _network;

            _server = next_address();

            std::size_t mask_bits = std::stol( network.substr( slash + 1 ) );
            if ( mask_bits < 0 || mask_bits > 32 ) throw std::invalid_argument( "Address mask must be 0-32 but is " + network.substr( slash + 1 ) );
            _mask.S_un.S_addr = htonl( 0xFFFFFFFF << ( 32 - mask_bits ) );

        }

        in_addr next_address() const {

            _next.S_un.S_addr = htonl( ntohl( _next.S_un.S_addr ) + 1 );
            return _next;

        }

        bool using_dns() const {

            return _using_dns;

        }

        bool using_intranet() const {

            return _using_intranet;

        }

        const std::string& endpoint() const {

            return _endpoint;

        }

        uint16_t bind() const {

            return _bind;

        }

        const std::vector<std::string>& peers() const {

            return _peers;

        }

        const in_addr& network_address() const {

            return _network;

        }

        const in_addr& server_address() const {

            return _server;
            
        }

        const in_addr& network_mask() const {

            return _mask;

        }

        const KeyPair& server_keypair() const {

            return _server_keypair;

        }

        const std::string& get_interface() const {

            return _interface;

        }



    private:

        std::string _interface;
        const KeyPair _server_keypair;
        bool _using_dns, _using_intranet;
        std::string _endpoint;
        uint16_t _bind;
        std::vector<std::string> _peers;
        in_addr _network, _server, _mask;
        mutable in_addr _next;

};


class Peer {

    public:

        Peer( const Config& config, const std::string& name, const in_addr& address, const in_addr& mask ) :
            _config( config ),
            _name( name ),
            _address( address ),
            _mask( mask ),
            _keypair( generate_keypair() ) {}

        
        std::filesystem::path save( const std::filesystem::path& directory ) const {

            const std::filesystem::path filename = directory / ( _name + ".conf" );
            std::ofstream file( filename );

            file << "# File generated by WireGuard Config Generator (C) 2025 sweet-bbq-sauce" << endline;
            file << "# Peer: " << _name << endline;
            file << endline;

            file << "[Interface]" << endline;
            file << "PrivateKey = " << base64( _keypair.private_key ) << endline;
            file << "Address = " << stringify( _address, _mask ) << endline;

            if ( _config.using_dns() ) file << "DNS = " << stringify( _config.server_address() ) << endline;

            file << endline;

            file << "[Peer]" << endline;
            file << "PublicKey = " << base64( _config.server_keypair().public_key ) << endline;
            file << "AllowedIPs = " << stringify( _config.network_address(), _mask ) << endline;
            file << "Endpoint = " << _config.endpoint() << endline;
            file << "PersistentKeepalive = 25" << endline;

            return filename;

        }


        const std::string& name() const {

            return _name;

        }

        std::string dns_name() const {

            return _name + ".vpn";

        }

        const in_addr& address() const {

            return _address;

        }

        const in_addr& mask() const {

            return _mask;

        }

        const KeyPair& keypair() const {

            return _keypair;

        }


    private:

        const Config& _config;
        const std::string _name;
        const in_addr _address, _mask;
        const KeyPair _keypair;

};


int main( const int argn, const char* argv[] ) {


    const std::string help = "Usage: ./gen <config_json> <output_directory>";
    if ( argn != 3 ) throw std::invalid_argument( help );

    const std::filesystem::path input = argv[1];
    if ( !std::filesystem::is_regular_file( input ) ) throw std::invalid_argument( help );

    const std::filesystem::path output = argv[2];
    if ( !std::filesystem::is_directory( output ) ) throw std::invalid_argument( help );


    if ( sodium_init() == -1 ) {

        std::cerr << "Błąd inicjalizacji libsodium" << std::endl;
        return EXIT_FAILURE;

    }


    const Config config( input );

    std::vector<Peer> peers;

    for ( const auto& peer : config.peers() ) {

        peers.emplace_back( config, peer, config.next_address(), config.network_mask() );
        peers.back().save( output );

    }

    std::ofstream file( output / ( config.get_interface() + ".conf" ) );

    file << "# File generated by WireGuard Config Generator (C) 2025 sweet-bbq-sauce" << endline << endline;
    file << "[Interface]" << endline;
    file << "PrivateKey = " << base64( config.server_keypair().private_key ) << endline;
    file << "Address = " << stringify( config.server_address(), config.network_mask() ) << endline;
    file << "ListenPort = " << config.bind() << endline << endline;

    in_addr full_mask;
    full_mask.S_un.S_addr = htonl( 0xFFFFFFFF );

    for ( const auto& peer : peers ) {

        file << "# " << peer.name() << endline;
        file << "PublicKey = " << base64( peer.keypair().public_key ) << endline;
        file << "AllowedIPs = " << stringify( peer.address(), full_mask ) << endline << endline;

    }

    if ( config.using_dns() ) {

        std::ofstream dnsmasq( output / ( config.get_interface() + "-dnsmasq.conf" ) );

        dnsmasq << "# File generated by WireGuard Config Generator (C) 2025 sweet-bbq-sauce" << endline << endline;
        dnsmasq << "interface=" << config.get_interface() << endline << endline;

        for ( const auto& peer : peers ) dnsmasq << "address=/" << peer.dns_name() << "/" << stringify( peer.address() ) << endline;

    }

    return EXIT_SUCCESS;


}