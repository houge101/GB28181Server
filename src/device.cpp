#include "device.h"
#include "spdlog/spdlog.h"
#include "pugixml.hpp"
#include "gb28181_header_maker.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <string>
#include <sstream>
#include <thread>
#include <tuple> 
#include <iostream>

#include "Log.h"
extern "C"{
#include "HTTPDigest.h"
}


static int SN_MAX = 99999999;
static int sn;

static int get_sn() {
	if (sn >= SN_MAX) {
		sn = 0;
	}
	sn++;
	return sn;
}

void Device::push_rtp_stream() {
    is_pushing = true;
	printf("push_rtp_stream begin!\r\n");
    auto status = this->bind();
    if (status != 0) {
        spdlog::error("device bind socket address failed: {}", status);
        return ;
    }

	char ps_header[PS_HDR_LEN];

	char ps_system_header[SYS_HDR_LEN];

	char ps_map_header[PSM_HDR_LEN];

	char pes_header[PES_HDR_LEN];

	char rtp_header[RTP_HDR_LEN];    

	int time_base = 90000;
	int fps = 24;
	int send_packet_interval = 1000 / fps;

	int interval = time_base / fps;
	long pts = 0;

	char frame[1024 * 128];

	int single_packet_max_length = 1400;

	char rtp_packet[RTP_HDR_LEN+1400];

	// int ssrc = 0xffffffff;
	int rtp_seq = 0;

    // Nalu *nalu = new Nalu();
	// nalu->packet = (char *)malloc(1024*128);
	// nalu->length = 1024 * 128;

    while (is_pushing) {
        for (auto i = 0; i < nalu_vector.size(); i++) {
            auto nalu = nalu_vector.at(i);

            NaluType  type = nalu->type;
            int length = nalu->length;
            char * packet = nalu->packet;

            int index = 0;
            if (NALU_TYPE_IDR == type) {
                gb28181_make_ps_header(ps_header, pts);

                memcpy(frame,ps_header,PS_HDR_LEN);
                index += PS_HDR_LEN;

                gb28181_make_sys_header(ps_system_header, 0x3f);

                memcpy(frame+ index, ps_system_header, SYS_HDR_LEN);
                index += SYS_HDR_LEN;

                gb28181_make_psm_header(ps_map_header);

                memcpy(frame + index, ps_map_header, PSM_HDR_LEN);
                index += PSM_HDR_LEN;

            } else {
                gb28181_make_ps_header(ps_header, pts);

                memcpy(frame, ps_header, PS_HDR_LEN);
                index += PS_HDR_LEN;
            }

            //灏佽pes
            gb28181_make_pes_header(pes_header, 0xe0, length, pts, pts);

            memcpy(frame+index, pes_header, PES_HDR_LEN);
            index += PES_HDR_LEN;

            memcpy(frame + index, packet, length);
            index += length;

            //缁勫寘rtp

            int rtp_packet_count = ((index - 1) / single_packet_max_length) + 1;

            for (int i = 0; i < rtp_packet_count; i++) {

                gb28181_make_rtp_header(rtp_header, rtp_seq, pts, atoi(ssrc.c_str()), i == (rtp_packet_count - 1));

                int writed_count = single_packet_max_length;

                if ((i + 1)*single_packet_max_length > index) {
                    writed_count = index - (i* single_packet_max_length);
                }
                //娣诲姞鍖呴暱瀛楄妭
                int rtp_start_index=0;

                unsigned short rtp_packet_length = RTP_HDR_LEN + writed_count;
                if (rtp_protocol == "TCP/RTP/AVP") {
                    unsigned char packt_length_ary[2];
                    packt_length_ary[0] = (rtp_packet_length >> 8) & 0xff;
                    packt_length_ary[1] = rtp_packet_length & 0xff;
                    memcpy(rtp_packet, packt_length_ary, 2);
                    rtp_start_index = 2;
                }

                memcpy(rtp_packet+ rtp_start_index, rtp_header, RTP_HDR_LEN);
                memcpy(rtp_packet+ +rtp_start_index + RTP_HDR_LEN, frame+ (i* single_packet_max_length), writed_count);
                rtp_seq++;

                if (is_pushing) {
                    send_network_packet(rtp_packet, rtp_start_index + rtp_packet_length);
                }
                else {
                    if (nalu != nullptr) {
                        delete nalu;
                        nalu = nullptr;
                    }
                    return;
                }
            }

            pts += interval;

            std::this_thread::sleep_for(std::chrono::milliseconds(send_packet_interval));
        }
    }

    is_pushing = false;
}

void Device::start() {
    spdlog::info("sip init begin.");

    sip_context = eXosip_malloc();

    if (OSIP_SUCCESS != eXosip_init(sip_context)) {
        spdlog::error("sip init failed.");
        return;
    }

    if (OSIP_SUCCESS != eXosip_listen_addr(sip_context, IPPROTO_UDP, nullptr, local_port, AF_INET, 0)) {
        spdlog::critical("sip port bind failed.");
        eXosip_quit(sip_context);
        sip_context = nullptr;
        return;
    }

    // run
    is_running = true;

    ostringstream from_uri;
    ostringstream contact;
    ostringstream proxy_uri;

    // local ip & port
    eXosip_guess_localip(sip_context, AF_INET, (char*)local_ip.data(), local_ip.length());
    spdlog::info("local ip is {}", local_ip);

    from_uri << "sip:" << device_sip_id << "@" << local_ip << ":" << local_port;
    contact << "sip:" << device_sip_id << "@" << local_ip << ":" << local_port;
    proxy_uri << "sip:" << server_sip_id << "@" << server_ip << ":" << server_port;

    from_sip = from_uri.str();
    to_sip = proxy_uri.str();

    spdlog::info("from uri is {}", from_sip);
    spdlog::info("contact is {}", contact.str());
    spdlog::info("proxy_uri is {}", to_sip);

    // clear auth
    eXosip_clear_authentication_info(sip_context);

    osip_message_t * register_message = nullptr;
    int register_id = eXosip_register_build_initial_register(sip_context, from_sip.c_str(), 
                    to_sip.c_str(), 
                    contact.str().c_str(), 3600, &register_message);
    if (nullptr == register_message) {
        spdlog::error("eXosip_register_build_initial_register failed");
        return;
    }

	invite_answer_msg = nullptr;
    eXosip_lock(sip_context);
	eXosip_register_send_register(sip_context, register_id, register_message);
	eXosip_unlock(sip_context);

    thread heartbeat_task_thread(&Device::heartbeat_task, this);
    heartbeat_task_thread.detach();

    this->process_request();
}

void Device::response_register_401unauthorized(shared_ptr<eXosip_event_t> evtp) {

    char *dest = nullptr;
    osip_message_t * reg = nullptr;
    osip_www_authenticate_t * header = nullptr;

    osip_www_authenticate_init(&header);
    osip_www_authenticate_set_auth_type (header, osip_strdup("Digest"));
    osip_www_authenticate_set_realm(header,osip_enquote(domain.c_str()));
    osip_www_authenticate_set_nonce(header,osip_enquote(device_num.c_str()));
    osip_www_authenticate_to_str(header, &dest);
    int ret = eXosip_message_build_answer (sip_context, evtp->tid, 401, &reg);
    if ( ret == 0 && reg != nullptr ) {
        osip_message_set_www_authenticate(reg, dest);
        osip_message_set_content_type(reg, "Application/MANSCDP+xml");
        eXosip_lock(sip_context);
        eXosip_message_send_answer (sip_context, evtp->tid,401, reg);
        eXosip_unlock(sip_context);
        spdlog::info("response_register_401unauthorized success");
    }else {
        spdlog::info("response_register_401unauthorized error");
    }

    osip_www_authenticate_free(header);
    osip_free(dest);

}


void Device::response_message_answer(shared_ptr<eXosip_event_t> evtp,int code){

    int returnCode = 0 ;
    osip_message_t * pRegister = nullptr;
    returnCode = eXosip_message_build_answer (sip_context,evtp->tid,code,&pRegister);
    bool bRegister = false;
    if(pRegister){
        bRegister = true;
    }
    if (returnCode == 0 && bRegister)
    {
        eXosip_lock(sip_context);
        eXosip_message_send_answer (sip_context,evtp->tid,code,pRegister);
        eXosip_unlock(sip_context);
    }
    else{
        spdlog::info("code={}",code);
        spdlog::info("returnCode={}",returnCode);
        spdlog::info("bRegister={}",bRegister);
    }

}

int Device::video_invite_answer(const char *device, const char *userIp, int userPort, shared_ptr<eXosip_event_t> evtp) {
    spdlog::info("video INVITE");

    char sdp[2048] = {0};

    LOGI("video_invite_answer  getSipId : %s, getIp : %s, getPort %d, device : %s,  userIp : %s, userPort : %d\r\n", device_sip_id.c_str(), local_ip.c_str(), local_port, device, userIp, userPort);

    snprintf (sdp, 2048,
              "v=0\r\n"
              "o=%s 0 0 IN IP4 %s\r\n"
              "s=Play\r\n"
              "c=IN IP4 %s\r\n"
              "t=0 0\r\n"
              "m=video %d RTP/AVP 96 97 98\r\n"
              "a=rtpmap:96 PS/90000\r\n"
              "a=rtpmap:97 MPEG4/90000\r\n"
              "a=rtpmap:98 H264/90000\r\n"
              "a=recvonly\r\n"
              "y=0100000001\r\n",
              device_num.c_str(), local_ip.c_str(), local_ip.c_str(), userPort);

    osip_message_set_body(invite_answer_msg, sdp, strlen(sdp));
    osip_message_set_content_type(invite_answer_msg, "application/sdp");
	
	int call_id = eXosip_call_send_answer(sip_context, reptid, 200, invite_answer_msg);

	char *s;
	size_t len;
   	osip_message_to_str(invite_answer_msg, &s, &len);

    if (call_id == OSIP_SUCCESS) {
		LOGI("200OK Send Begin : %s\n",s);
        LOGI("eXosip_call_send_initial_invite success: call_id=%d",call_id);
    }else{
        LOGE("eXosip_call_send_initial_invite error: call_id=%d",call_id);
    }

    return 0;
}


int Device::request_invite(const char *device, const char *userIp, int userPort) {
    spdlog::info("INVITE");

    char session_exp[1024] = { 0 };
    osip_message_t *msg = nullptr;
    char from[1024] = {0};
    char to[1024] = {0};
    char contact[1024] = {0};
    char sdp[2048] = {0};
    char head[1024] = {0};
    char subject[128] = { 0 };

    LOGI("getSipId : %s, getIp : %s, getPort %d, device : %s,  userIp : %s, userPort : %d\r\n", device_sip_id.c_str(), local_ip.c_str(), local_port, device, userIp, userPort);

    sprintf(to, "sip:%s@%s:%d", device_num.c_str(), userIp, userPort);
    sprintf(from, "sip:%s@%s", device_sip_id.c_str(),local_ip.c_str());
    //sprintf(contact, "sip:%s@%s:%d", mInfo->getNonce(),mInfo->getIp(), mInfo->getPort());
    snprintf(subject, 128, "%s:0,%s:0", device_num.c_str(), device_sip_id.c_str());
    int ret = eXosip_call_build_initial_invite(sip_context, &msg, to, from, nullptr, subject);

    snprintf (sdp, 2048,
              "v=0\r\n"
              "o=%s 0 0 IN IP4 %s\r\n"
              "s=Play\r\n"
              "c=IN IP4 %s\r\n"
              "t=0 0\r\n"
              "m=video %d RTP/AVP 96 97 98\r\n"
              "a=rtpmap:96 PS/90000\r\n"
              "a=rtpmap:97 MPEG4/90000\r\n"
              "a=rtpmap:98 H264/90000\r\n"
              "a=recvonly\r\n"
              "y=0100000001\r\n",
              device_num.c_str(), local_ip.c_str(), local_ip.c_str(), RTPPORT);

    if (ret) {
        LOGE( "eXosip_call_build_initial_invite error: %s %s ret:%d", from, to, ret);
        return -1;
    }

    osip_message_set_body(msg, sdp, strlen(sdp));
    osip_message_set_content_type(msg, "application/sdp");
 //   snprintf(session_exp, sizeof(session_exp)-1, "%i;refresher=uac", mInfo->getTimeout());
 //   osip_message_set_header(msg, "Session-Expires", session_exp);
 //   osip_message_set_supported(msg, "timer");

    int call_id = eXosip_call_send_initial_invite(sip_context, msg);

    if (call_id > 0) {
        LOGI("eXosip_call_send_initial_invite success: call_id=%d",call_id);
    }else{
        LOGE("eXosip_call_send_initial_invite error: call_id=%d",call_id);
    }
    return ret;
}

void Device::response_register(shared_ptr<eXosip_event_t> evtp) {

		osip_authorization_t * auth = nullptr;
		osip_message_get_authorization(evtp->request, 0, &auth);
	
		if(auth && auth->username){
	
			char *method = NULL, // REGISTER
			*algorithm = NULL, // MD5
			*username = NULL,// 340200000013200000024
			*realm = NULL, // sip服务器传给客户端，客户端携带并提交上来的sip服务域
			*nonce = NULL, //sip服务器传给客户端，客户端携带并提交上来的nonce
			*nonce_count = NULL,
			*uri = NULL; // sip:34020000002000000001@3402000000
	
			osip_contact_t *contact = nullptr;
			osip_message_get_contact (evtp->request, 0, &contact);
	
			method = evtp->request->sip_method;
			char calc_response[HASHHEXLEN];
			HASHHEX HA1, HA2 = "", Response;
	
#define SIP_STRDUP(field) if (auth->field) (field) = osip_strdup_without_quote(auth->field)
	
			SIP_STRDUP(algorithm);
			SIP_STRDUP(username);
			SIP_STRDUP(realm);
			SIP_STRDUP(nonce);
			SIP_STRDUP(nonce_count);
			SIP_STRDUP(uri);
	
	
			DigestCalcHA1(algorithm, username, realm, password.c_str(), nonce, nonce_count, HA1);
			DigestCalcResponse(HA1, nonce, nonce_count, auth->cnonce, auth->message_qop, 0, method, uri, HA2, Response);
	
			HASHHEX temp_HA1;
			HASHHEX temp_response;
			DigestCalcHA1("REGISTER", username, domain.c_str(), password.c_str(), device_num.c_str(), NULL, temp_HA1);
			DigestCalcResponse(temp_HA1, device_num.c_str(), NULL, NULL, NULL, 0, method, uri, NULL, temp_response);
			memcpy(calc_response, temp_response, HASHHEXLEN);
	/*
			Client* client = new Client(strdup(contact->url->host),
					atoi(contact->url->port),
					strdup(username));
			Client* client = new Client(strdup(contact->url->host),
				local_port,
				strdup(username));*/
	
			if (!memcmp(calc_response, Response, HASHHEXLEN)) {
				this->response_message_answer(evtp,200);
				LOGI("Camera registration succee,ip=%s,port=%d,device=%s",strdup(contact->url->host), atoi(contact->url->port),strdup(username));
	
				//mClientMap.insert(std::make_pair(client->getDevice(),client));	
				//this->request_invite(client->getDevice(),client->getIp(),client->getPort());
				//IPC
				//this->request_invite(strdup(username),strdup(contact->url->host),atoi(contact->url->port));
					
			} else {
				this->response_message_answer(evtp,401);
				LOGI("Camera registration error, p=%s,port=%d,device=%s",strdup(contact->url->host),local_port,strdup(username));
	
			//	delete client;
			}

			ipc_id = username;
			ipc_ip = contact->url->host;
			ipc_port = atoi(contact->url->port);
	
			osip_free(algorithm);
			osip_free(username);
			osip_free(realm);
			osip_free(nonce);
			osip_free(nonce_count);
			osip_free(uri);
		} else {
			response_register_401unauthorized(evtp);
		}

}

void Device::response_invite_ack(shared_ptr<eXosip_event_t> evtp){
	char *s;
	size_t len;

    osip_message_t* msg = nullptr;
    int ret = eXosip_call_build_ack(sip_context, evtp->did, &msg);
    if (!ret && msg) {
        eXosip_call_send_ack(sip_context, evtp->did, msg);
    	osip_message_to_str(evtp->request, &s, &len);
    	LOGI("\nprint request start\ntype=%d\n%s\nprint request end\n",evtp->type,s);
    } else {
        LOGE("eXosip_call_send_ack error=%d", ret);
    }

}

void Device::sip_print(shared_ptr<eXosip_event_t> evtp) {
    char *s;
    size_t len;
    osip_message_to_str(evtp->request, &s, &len);
    LOGI("\nsip_print request start\ntype=%d\n%s\nsip_print request end\n",evtp->type,s);
    osip_message_to_str(evtp->response, &s, &len);
    LOGI("\nsip_print response start\ntype=%d\n%s\nsip_print response end\n",evtp->type,s);
}


void Device::dump_request(shared_ptr<eXosip_event_t> evtp) {
    char *s;
    size_t len;
    osip_message_to_str(evtp->request, &s, &len);
    LOGI("\nprint request start\ntype=%d\n%s\nprint request end\n",evtp->type,s);
}

void Device::dump_response(shared_ptr<eXosip_event_t> evtp) {
    char *s;
    size_t len;
    osip_message_to_str(evtp->response, &s, &len);
    LOGI("\nprint response start\ntype=%d\n%s\nprint response end\n",evtp->type,s);
}

osip_message_t* Device::invite_200OK(shared_ptr<eXosip_event_t> event)
{
/*
	// 创建一个空的200 OK消息
	osip_message_t *message = NULL;
	eXosip_lock();
    eXosip_message_build_answer(sip_context, event->tid, 200, &msg);
	eXosip_unlock();
	
	// 设置通用头字段
	osip_from_t *from = osip_from_parse(eXosip_event_get_header(event, "From", 0));
	osip_message_set_from(message, from);
	osip_to_t *to = osip_to_parse(eXosip_event_get_header(event, "To", 0));
	osip_message_set_to(message, to);
	osip_cseq_t *cseq = osip_cseq_parse(osip_message_get_header(message, "CSeq", 0));
	osip_message_set_cseq(message, cseq);
	osip_call_id_t *callid = osip_call_id_parse(eXosip_event_get_header(event, "Call-ID", 0));
	osip_message_set_call_id(message, callid);
	
	// 设置特定头字段
	osip_message_set_header(message, "Contact", "<sip:localhost:5069>");
	osip_message_set_header(message, "Content-Type", "application/sdp");
	osip_message_set_header(message, "User-Agent", "LibOSIP2");
	
	// 设置消息内容
	osip_message_set_reason_phrase(message, "OK");
	osip_message_set_body(message, "v=0\r\no=root 1234 5678 IN IP4 192.168.0.1\r\ns=session\r\nc=IN IP4 192.168.0.1\r\nt=0 0\r\na=sendonly\r\nm=video 5000 RTP/AVP 96");
	
	// 序列化消息并发送
	char *msgstr;
	int len = osip_message_to_str(message, &msgstr);
	if (len == OSIP_SUCCESS) {
		// 将msgstr发送到目标地址
		printf("SIP Message:\n%s\n", msgstr);
		osip_free(msgstr);
	}
	
	// 释放消息
	osip_message_free(message);
*/
}
void Device::process_request() {
//	std::string httpStr;
//	sdp_message_t *sdp_msg;
//	sdp_media_t * video_sdp;
//	sdp_connection_t *connection;
    while (is_running) {
        auto evt = shared_ptr<eXosip_event_t>(
            eXosip_event_wait(sip_context, 0, 100),
            eXosip_event_free);

        eXosip_lock(sip_context);
        eXosip_automatic_action(sip_context);
        eXosip_unlock(sip_context);

        if (evt == nullptr) {
            continue;
        }

        switch (evt->type)
        {
        case eXosip_event_type::EXOSIP_REGISTRATION_SUCCESS: {
            spdlog::info("got REGISTRATION_SUCCESS");
            is_register = true;
            break;
        }
        case eXosip_event_type::EXOSIP_REGISTRATION_FAILURE: {
            spdlog::info("got REGISTRATION_FAILURE");
            if (evt->response == nullptr) {
                spdlog::error("register 401 has no response !!!");
                break;
            }

            if (401 == evt->response->status_code) {
                osip_www_authenticate_t * www_authenticate_header;

                osip_message_get_www_authenticate(evt->response, 0, &www_authenticate_header);

                if (eXosip_add_authentication_info(sip_context, device_sip_id.c_str(), username.c_str(), password.c_str(), 
                                    "MD5", www_authenticate_header->realm)) {
                    spdlog::error("register add auth failed");
                    break;
                };
            };
            break;
        }
        case eXosip_event_type::EXOSIP_MESSAGE_NEW: {
            spdlog::info("got MESSAGE_NEW");

			if (MSG_IS_REGISTER(evt->request))
			{
				this->response_register(evt);
			}
			else if (MSG_IS_MESSAGE(evt->request)) {
                osip_body_t * body = nullptr;
                osip_message_get_body(evt->request, 0, &body);
                if (body != nullptr) {
                    spdlog::info("new message request: \n{}", body->body);
                }

                this->send_response_ok(evt);

                auto cmd_sn = this->get_cmd(body->body);
                string cmd = get<0>(cmd_sn);
                string sn = get<1>(cmd_sn);
                spdlog::info("got new cmd: {}", cmd);
                if ("Catalog" == cmd) {
                    this->process_catalog_query(sn);
                } else if ("DeviceStatus" == cmd) {
                    this->process_devicestatus_query(sn);
                } else if ("DeviceInfo" == cmd) {
                    this->process_deviceinfo_query(sn);
                } else if ("DeviceControl" == cmd) {
                    this->process_devicecontrol_query(sn);
                } else {
                    spdlog::error("unhandled cmd: {}", cmd);
                }
            } else if (MSG_IS_BYE(evt->request)) {
                spdlog::info("got BYE message");
                this->send_response_ok(evt);
                break;
            }
            break;
        }
        case eXosip_event_type::EXOSIP_CALL_INVITE: {
            spdlog::info("got CALL_INVITE");
			reptid = evt->tid;
		
            int status = eXosip_call_build_answer(sip_context, evt->tid, 200, &invite_answer_msg);
			if (status != 0) {
                spdlog::error("call invite build answer failed");
                break;
            }
			
            osip_message_t * message = evt->request;
			
            status = eXosip_call_build_answer(sip_context, evt->tid, 181, &message);
            if (status != 0) {
                spdlog::error("call invite build answer failed");
                break;
            }
			
            eXosip_call_send_answer(sip_context, evt->tid, 181, message);
			this->sip_print(evt);
			
			spdlog::info("ipc_id:   ipc_ip:   ipc_port {}:{}:{}",ipc_id, ipc_ip, ipc_port);

			this->request_invite(ipc_id.c_str(), ipc_ip.c_str(), ipc_port);
//	        is_pushing = true;
            auto sdp_msg = eXosip_get_remote_sdp(sip_context, evt->did);
            if (!sdp_msg) {
                spdlog::error("eXosip_get_remote_sdp failed");
                break;
            }

            auto connection = eXosip_get_video_connection(sdp_msg);
            if (!connection) {
                spdlog::error("eXosip_get_video_connection failed");
                break;                
            }

            rtp_ip = connection->c_addr;

            auto video_sdp = eXosip_get_video_media(sdp_msg);
            if (!video_sdp) {
                spdlog::error("eXosip_get_video_media failed");
                break;                  
            }

            rtp_port = atoi(video_sdp->m_port);

            spdlog::info("rtp server: {}:{}", rtp_ip, rtp_port);

            rtp_protocol = video_sdp->m_proto;

            spdlog::info("rtp protocol: {}", rtp_protocol);
/*
            osip_body_t *sdp_body = NULL;
			osip_message_get_body(evt->request, 0, &sdp_body);
            if (nullptr == sdp_body) {
                spdlog::error("osip_message_get_body failed");
                break; 
            }

            string body = sdp_body->body;
            auto y_sdp_first_index = body.find("y=");
            auto y_sdp = body.substr(y_sdp_first_index);
            auto y_sdp_last_index = y_sdp.find("\r\n");
            ssrc = y_sdp.substr(2, y_sdp_last_index-1);
            spdlog::info("ssrc: {}", ssrc);

            stringstream ss;
            ss << "v=0\r\n";
            ss << "o=" << device_sip_id << " 0 0 IN IP4 " << local_ip << "\r\n";
            ss << "s=Play\r\n";
            ss << "c=IN IP4 " << local_ip << "\r\n";
            ss << "t=0 0\r\n";
            if (rtp_protocol == "TCP/RTP/AVP") {
                ss << "m=video " << local_port << " TCP/RTP/AVP 96\r\n";
            }
            else {
                ss << "m=video " << local_port << " RTP/AVP 96\r\n";
            }
            ss << "a=sendonly\r\n";
            ss << "a=rtpmap:96 PS/90000\r\n";
            ss << "y=" << ssrc << "\r\n";
            string sdp_output_str  = ss.str();

            size_t size = sdp_output_str.size();

            //osip_message_t * message = evt->request;
            //int status = eXosip_call_build_answer(sip_context, evt->tid, 200, &message);
            
			eXosip_call_build_answer(sip_context, evt->tid, 200, &message);

            if (status != 0) {
                spdlog::error("call invite build answer failed");
                break;
            }
            
            osip_message_set_content_type(message, "APPLICATION/SDP");
            osip_message_set_body(message, sdp_output_str.c_str(), sdp_output_str.size());

            eXosip_call_send_answer(sip_context, evt->tid, 200, message);

            spdlog::info("reply call invite: \n{}", sdp_output_str);
*/
            break;
        }
        case eXosip_event_type::EXOSIP_CALL_ACK: {
            spdlog::info("got CALL_ACK: begin pushing rtp stream...");
            if (is_pushing) {
                spdlog::info("already pushing rtp stream");
            } else {			
            //this->response_invite_ack(evt);
            
			//thread t(&Device::push_rtp_stream, this);
            //t.detach();
            is_pushing=true;
			std::string httpStr = "http://192.168.50.130:18082/index/api/startSendRtp?secret=035c73f7-bb6b-4889-a715-d9eb2d1925cc&vhost=__defaultVhost__&app=rtp&stream=";//test&ssrc=06F5E666&dst_url=";
			httpStr.append("05F5E101").append("&ssrc=100000001&dst_url=");
			httpStr.append(rtp_ip).append("&dst_port=");
			httpStr += std::to_string(rtp_port);
			httpStr.append("&is_udp=1");
			spdlog::info("httpStr : {}",httpStr);
			sleep(2);			
			curl_easy_setopt(curl, CURLOPT_URL,httpStr.c_str());
	        res = curl_easy_perform(curl);   // 执行
	        if(CURLE_OK == res)
	        {
				spdlog::info("Http Url Send Ok!");
				break;
			}
			else
			{
				spdlog::info("Http Url Send Failed! : {}",res);
				break;
			}
			
            }
            break;
        }
        case eXosip_event_type::EXOSIP_CALL_CLOSED: {
            spdlog::info("got CALL_CLOSED: stop pushing rtp stream...");
			is_pushing = false;
            break;
        }
        case eXosip_event_type::EXOSIP_MESSAGE_ANSWERED: {
            spdlog::info("got MESSAGE_ANSWERED: unhandled");
            break;
        }
        case eXosip_event_type::EXOSIP_CALL_PROCEEDING:{//5
            LOGI("EXOSIP_CALL_PROCEEDING type=%d: When the server receives the Invite (SDP) confirmation reply from the client", evt->type);
            this->dump_request(evt);
            this->dump_response(evt);
            break;
        }
        case eXosip_event_type::EXOSIP_CALL_ANSWERED:{// 7
            LOGI("EXOSIP_CALL_ANSWERED type=%d: The server receives an invite (SDP) confirmation reply from the client", evt->type);
            this->dump_request(evt);
            this->dump_response(evt);

            this->response_invite_ack(evt);

			video_invite_answer(server_sip_id.c_str(),server_ip.c_str(),server_port,evt);
            break;
        }
        default: {
            spdlog::info("unhandled sip evt type: {}", evt->type);
            break;
        }
        }
    }
}

void Device::process_catalog_query(string sn) {
    stringstream ss;
    ss << "<?xml version=\"1.0\" encoding=\"GB2312\"?>\r\n";
    ss << "<Response>\r\n";
    ss << "<CmdType>Catalog</CmdType>\r\n";
    ss << "<SN>" << sn << "</SN>\r\n";
    ss << "<DeviceID>" << device_sip_id << "</DeviceID>\r\n";
    ss << "<SumNum>" << 1 << "</SumNum>\r\n";
    ss << "<DeviceList Num=\"" << 1 << "\">\r\n";
    ss << "<Item>\r\n";
    ss << "<DeviceID>" << device_sip_id << "</DeviceID>\r\n";
    ss << "<Manufacturer>" << manufacture << "</Manufacturer>\r\n";
    ss << "<Status>ON</Status>\r\n";
    ss << "<Name>IPC</Name>\r\n";
    ss << "<ParentID>" << server_sip_id << "</ParentID>\r\n";
    ss << "</Item>\r\n";
    ss << "</DeviceList>\r\n";
    ss << "</Response>\r\n";
    spdlog::info("catalog response: \n{}", ss.str());
    auto request = create_msg();
    if (request != NULL) {
        osip_message_set_content_type(request, "Application/MANSCDP+xml");
        osip_message_set_body(request, ss.str().c_str(), strlen(ss.str().c_str()));
        send_request(request);
    }
}

void Device::process_devicestatus_query(string sn) {
    stringstream ss;

    time_t rawtime;
    struct tm* timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    char curtime[72] = {0};
    sprintf(curtime, "%d-%d-%dT%02d:%02d:%02d", (timeinfo->tm_year + 1900), (timeinfo->tm_mon + 1),
                        timeinfo->tm_mday, timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);    
    
    ss << "<?xml version=\"1.0\"?>\r\n";
    ss << "<Response>\r\n";
    ss << "<CmdType>DeviceStatus</CmdType>\r\n";
    ss << "<SN>" << get_sn() << "</SN>\r\n";
    ss << "<DeviceID>" << device_sip_id << "</DeviceID>\r\n";
    ss << "<Result>OK</Result>\r\n";
    ss << "<Online>ONLINE</Online>\r\n";
    ss << "<Status>OK</Status>\r\n";
    ss << "<DeviceTime>" << curtime << "</DeviceTime>\r\n";
    ss << "<Alarmstatus Num=\"0\">\r\n";
    ss << "</Alarmstatus>\r\n";
    ss << "<Encode>ON</Encode>\r\n";
    ss << "<Record>OFF</Record>\r\n";
    ss << "</Response>\r\n";

    spdlog::info("devicestatus response: \n{}", ss.str());
    auto request = create_msg();
    if (request != NULL) {
        osip_message_set_content_type(request, "Application/MANSCDP+xml");
        osip_message_set_body(request, ss.str().c_str(), strlen(ss.str().c_str()));
        send_request(request);
    }
}

void Device::process_deviceinfo_query(string sn) {
    stringstream ss;

    ss << "<?xml version=\"1.0\"?>\r\n";
    ss <<    "<Response>\r\n";
    ss <<    "<CmdType>DeviceInfo</CmdType>\r\n";
    ss <<    "<SN>" << get_sn() << "</SN>\r\n";
    ss <<    "<DeviceID>" << device_sip_id << "</DeviceID>\r\n";
    ss <<    "<Result>OK</Result>\r\n";
    ss <<    "<DeviceType>simulate client</DeviceType>\r\n";
    ss <<    "<Manufacturer>ZHD</Manufacturer>\r\n";
    ss <<    "<Model>28181</Model>\r\n";
    ss <<    "<Firmware>fireware</Firmware>\r\n";
    ss <<    "<MaxCamera>1</MaxCamera>\r\n";
    ss <<    "<MaxAlarm>0</MaxAlarm>\r\n";
    ss <<    "</Response>\r\n";

    spdlog::info("deviceinfo response: \n{}", ss.str());
    auto request = create_msg();
    if (request != NULL) {
        osip_message_set_content_type(request, "Application/MANSCDP+xml");
        osip_message_set_body(request, ss.str().c_str(), strlen(ss.str().c_str()));
        send_request(request);
    }
}

void Device::process_devicecontrol_query(string sn) {

}

void Device::heartbeat_task() {
	while (true) {
        if (is_register) {
            stringstream ss;
            ss << "<?xml version=\"1.0\"?>\r\n";
            ss << "<Notify>\r\n";
            ss << "<CmdType>Keepalive</CmdType>\r\n";
            ss << "<SN>" << get_sn() << "</SN>\r\n";
            ss << "<DeviceID>" << device_sip_id << "</DeviceID>\r\n";
            ss << "<Status>OK</Status>\r\n";
            ss << "</Notify>\r\n";

            osip_message_t* request = create_msg();
            if (request != NULL) {
                osip_message_set_content_type(request, "Application/MANSCDP+xml");
                osip_message_set_body(request, ss.str().c_str(), strlen(ss.str().c_str()));
                send_request(request);
                spdlog::info("sent heartbeat");
            }
        }

		std::this_thread::sleep_for(std::chrono::seconds(60));
	}
}

osip_message_t * Device::create_msg() {

    osip_message_t * request = nullptr;
    auto status = eXosip_message_build_request(sip_context, &request, "MESSAGE", to_sip.c_str(), from_sip.c_str(), nullptr);
    if (OSIP_SUCCESS != status) {
        spdlog::error("build request failed: {}", status);
    }

    return request;
}

void Device::send_request(osip_message_t * request) {
    eXosip_lock(sip_context);
    eXosip_message_send_request(sip_context, request);
    eXosip_unlock(sip_context);
}

void Device::send_response(shared_ptr<eXosip_event_t> evt, osip_message_t * msg) {
    eXosip_lock(sip_context);
    eXosip_message_send_answer(sip_context, evt->tid, 200, msg);
    eXosip_unlock(sip_context);
}

void Device::send_response_ok(shared_ptr<eXosip_event_t> evt) {
    auto msg = evt->request;
    eXosip_message_build_answer(sip_context, evt->tid, 200, &msg);
    send_response(evt, msg);
}

std::tuple<string, string> Device::get_cmd(const char * body) {
    pugi::xml_document document;

    if (!document.load(body)) {
        spdlog::error("cannot parse the xml");
        return make_tuple("", "");
    }

    pugi::xml_node root_node = document.first_child();

    if (!root_node) {
        spdlog::error("cannot get root node of xml");
        return make_tuple("", "");
    }

    string root_name = root_node.name();
    if ("Query" != root_name) {
        spdlog::error("invalid query xml with root: {}", root_name);
        return make_tuple("", "");
    }

    auto cmd_node = root_node.child("CmdType");

    if (!cmd_node) {
        spdlog::error("cannot get the cmd type");
        return make_tuple("", "");
    }

    auto sn_node = root_node.child("SN");

    if (!sn_node) {
        spdlog::error("cannot get the SN");
        return make_tuple("", "");
    }

    string cmd = cmd_node.child_value();
    string sn = sn_node.child_value();

    return make_tuple(cmd, sn);
}
