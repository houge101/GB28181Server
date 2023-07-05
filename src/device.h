#ifndef DEVICE_INCLUDE
#define DEVICE_INCLUDE

#include <string>
#include <tuple>
#include <memory>
#include "eXosip2/eXosip.h"
#include "load_h264.h"
#include "curl/curl.h"

using namespace std;

#define RTPPORT 10000

class Device {
public:
    Device() {}

    Device(string server_sip_id, string server_ip, int server_port,
            string device_sip_id, string username, string password,
            int local_port,
            string manufacture,
            string device_num,
            string domain,
            string filepath): 
            server_sip_id(server_sip_id), 
            server_ip(server_ip),
            server_port(server_port),
            device_sip_id(device_sip_id),
            username(username),
            password(password),
            local_port(local_port),
            manufacture(manufacture),
            device_num(device_num),
            domain(domain),
            filepath(filepath) {
        sip_context = nullptr;
        is_running = false;
        is_register = false;
		is_pushing = false;
        local_ip = string(128, '0');

		curl = curl_easy_init();
		if(!curl)
		{
			curl = nullptr;
			printf("curl Init Failed!");
		}
    //    load(filepath.c_str());
    }

    ~Device(){}

    void start();

    void stop();

    void response_register(shared_ptr<eXosip_event_t> evtp);

    void response_message_answer(shared_ptr<eXosip_event_t> evtp,int code);

	void response_register_401unauthorized(shared_ptr<eXosip_event_t> evtp);

	void sip_print(shared_ptr<eXosip_event_t> evtp);

	osip_message_t* invite_200OK(shared_ptr<eXosip_event_t> evtp);
	
	void dump_request(shared_ptr<eXosip_event_t> evtp);

	void dump_response(shared_ptr<eXosip_event_t> evtp);
	
	void response_invite_ack(shared_ptr<eXosip_event_t> evtp);
	
	int request_invite(const char *device, const char *userIp, int userPort);
	
	int video_invite_answer(const char *device, const char *userIp, int userPort,shared_ptr<eXosip_event_t> evtp);

    void process_request();

    void process_catalog_query(string sn);

    void process_deviceinfo_query(string sn);

    void process_devicestatus_query(string sn);

    void process_devicecontrol_query(string sn);

    void heartbeat_task();

    void send_request(osip_message_t * request);

    void send_response(shared_ptr<eXosip_event_t> evt, osip_message_t * msg);

    osip_message_t * create_msg();

    void send_response_ok(shared_ptr<eXosip_event_t> evt);

    std::tuple<string, string> get_cmd(const char * body);

    void push_rtp_stream();

public:
    string server_sip_id;
    string server_ip;
    int server_port;
    string device_sip_id;
    string username;
    string password;
    string local_ip;
    int local_port;

    string manufacture;
    string rtp_ip;
    int rtp_port;
    string rtp_protocol;

	string device_num;
	string domain;
    string filepath;

private:
    eXosip_t* sip_context;
	
	osip_message_t * invite_answer_msg;// = NULL;

	
    bool is_running;
    bool is_register;
    bool is_pushing;

    string from_sip;
    string to_sip;
    string ssrc;

	CURL *curl;
    CURLcode res;

	string ipc_ip;
	int ipc_port;
	string ipc_id;
	string ipc_domain;
	int reptid;

	
    int sockfd;
    int bind();
    void send_network_packet(const char * data, int length);
};

#endif
