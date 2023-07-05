#include <string>
#include "spdlog/spdlog.h"
#include "cxxopts.h"
#include "device.h"
#include "cJSON.h"
#include <pthread.h>
#include <unistd.h>
#include "SipServer.h"

using namespace std;

#define JSON_FILE_LENG          (200 * 1024)                                    //JSON文件大小
#define MAX_PATH          260

pthread_t revFromIPC; //处理接收IPC端GB协议线程
pthread_t sendToServer; //向Server端注册GB协议线程

typedef struct GBParams
{
	string server_id;// = "34070000002000000001";//级联平台的ID（wvp的sip.id值）
    string server_ip;// = "192.168.50.100";//级联平台的IP（wvp的sip.ip）
    int server_port;// = 5061;//级联平台的端口号（wvp的sip.port)
    string device_id;// = "34030000002000000001";//设备ID，用于下级设备级联此平台时定义的编号
    string device_domain;// = "3403000000";//设备域
    string device_ip;// = "192.168.50.130";//此软件所在设备的IP（wvp的sip.ip）
    int device_port;// = 5069;//此服务器的监听端口
    string device_num;// = "31011500991320000046";//设备编号，此服务器定义的通道编号
    string username;// = "admin";//此服务器的用户名密码，需保证下级，此server和级联平台相同
    string password;// = "zx123456";
    string manufacture;// = "LYY";//软件名称,可随意定义
}gbParams;

void *revIPCSip(void* arg)
{
	while(1)
	{
		spdlog::info("revIPCSip keepalive!");
		sleep(5*60);
	}
/*
	gbParams* gb = (gbParams*)arg;
    ServerInfo info(
            gb->manufacture.c_str(),
            gb->device_num.c_str(),
            gb->device_ip.c_str(),
            gb->device_port,
            10000,
            gb->device_id.c_str(),
            gb->device_domain.c_str(),
            gb->password.c_str(),
            1800,
            3600);

    SipServer sipServer(&info);
    sipServer.loop();
*/
}

void *sendServerSip(void* arg)
{
	gbParams* gb = (gbParams*)arg;
    string filepath = "/home/hjm/gb28181/GB28181-Server/samples/a.h264";
	auto device = shared_ptr<Device>(
			new Device(gb->server_id, gb->server_ip, gb->server_port, 
				gb->device_id, gb->username, gb->password, gb->device_port, gb->manufacture,
				gb->device_num,gb->device_domain,filepath)
			);
		device->start();

}

//从json文件读取相关配置信息
int parserIniFile(gbParams* gb)
{
	std::string strIniPath = "../GB28181.json";
	FILE * fp = fopen(strIniPath.c_str(), "r");

	if (NULL == fp)
	{	
		spdlog::info("Json Init File Open Failed!{}  ",strIniPath.c_str());
		return -1;
	}

	char* buf = NULL;
	buf = (char*)malloc(JSON_FILE_LENG);
	if (NULL != buf)
	{
		int numread;
		numread = fread(buf, 1, JSON_FILE_LENG, fp);
		spdlog::info("Read Num : {}", numread);
	}
	else
	{
		spdlog::info("Parameter Read Failed!");
		fclose(fp);
		return -1;
	}

	cJSON* root = cJSON_Parse(buf);
	if (!root)
	{
		spdlog::info("JSON Parse Failed! {}", cJSON_GetErrorPtr());
		fclose(fp);
		free(buf);
		return -1;
	}

	gb->manufacture = "SC";
	
	//获取相机登录名和密码
	cJSON* deal  = cJSON_GetObjectItem(root, "deal");
	cJSON* userName  = cJSON_GetObjectItem(root, "userName");
	cJSON* userPwd  = cJSON_GetObjectItem(root, "userPwd");

	gb->username = userName->valuestring;
	gb->password = userPwd->valuestring;
	

	//获取platform信息，即需要级联的上级平台（如wvp，孪生平台）的信息
	cJSON* platform = cJSON_GetObjectItem(root, "platform");
	cJSON* platform_id = cJSON_GetObjectItem(platform, "platform_id");
	cJSON* platform_port = cJSON_GetObjectItem(platform, "platform_port");
	cJSON* platform_ip = cJSON_GetObjectItem(platform, "platform_ip");

	gb->server_id = platform_id->valuestring;
	gb->server_port = platform_port->valueint;
	gb->server_ip = platform_ip->valuestring;
	spdlog::info("server_port : {}",gb->server_port);

	//获取本机平台信息，用于下级（IPC）级联到此平台
	cJSON* local = cJSON_GetObjectItem(root, "Local");
	cJSON* local_id = cJSON_GetObjectItem(local, "local_id");
	cJSON* local_domain = cJSON_GetObjectItem(local, "local_domain");
	cJSON* local_port = cJSON_GetObjectItem(local, "local_port");
	cJSON* local_ip = cJSON_GetObjectItem(local, "local_ip");

	gb->device_id = local_id->valuestring;
	gb->device_domain = local_domain->valuestring;
	gb->device_ip = local_ip->valuestring;
	gb->device_port = local_port->valueint;
	spdlog::info("device_port : {}",gb->device_port);

	//获取此设备的编号，可随意自定义
	cJSON* local_number = cJSON_GetObjectItem(local, "local_number");
	gb->device_num = local_number->valuestring;

#if 0
	cJSON* cameraInf = cJSON_GetObjectItem(root, "cameraInf");
	cJSON* camera = cJSON_GetObjectItem(cameraInf, "camera");

	g_liveVideoParams.cameraNum = cJSON_GetArraySize(camera);										//相机数量

	if (g_liveVideoParams.cameraNum > 0 && g_liveVideoParams.cameraNum < CAMERA_SUPPORT_MAX) {
		
		g_liveVideoParams.pCameraParams = (CameraParams *)malloc(sizeof(CameraParams)*g_liveVideoParams.cameraNum);
		if (g_liveVideoParams.pCameraParams == NULL) {
			fprintf(g_fp, "malloc, failed");
			return -1;
		}
		
		memset(g_liveVideoParams.pCameraParams, 0, sizeof(CameraParams)*g_liveVideoParams.cameraNum);
		CameraParams *p;
		p = g_liveVideoParams.pCameraParams;

		cJSON* cameraBody = cJSON_GetArrayItem(camera, 0);

		cJSON* camera_sip_id = cJSON_GetObjectItem(cameraBody, "camera_sip_id");
		cJSON* camera_recv_port = cJSON_GetObjectItem(cameraBody, "camera_recv_port");
		memcpy(p->sipId, camera_sip_id->valuestring, strlen(camera_sip_id->valuestring)>MAX_PATH?MAX_PATH:strlen(camera_sip_id->valuestring));//获取摄像头ID
		p->recvPort = camera_recv_port->valueint;

		memcpy(p->UserPwd, userPwd->valuestring, strlen(userPwd->valuestring)>MAX_PATH?MAX_PATH:strlen(userPwd->valuestring));//获取摄像头密码
		memcpy(p->UserName, userName->valuestring, strlen(userName->valuestring)>MAX_PATH?MAX_PATH:strlen(userName->valuestring));//获取摄像头用户名

		printf("UserPwd : %s, userName : %s, ini Path : %s\n", p->UserPwd, p->UserName, strIniPath.c_str());
	}

	g_liveVideoParams.gb28181Param.SN = 1;
	g_liveVideoParams.gb28181Param.call_id = -1;
	g_liveVideoParams.gb28181Param.dialog_id = -1;
	g_liveVideoParams.gb28181Param.registerOk = 0;
#endif
	spdlog::info("加载配置文件完成");

	fclose(fp);
	free(buf);
	return 0;
}


int main(int argc, const char* argv[]) {

	gbParams gb;
	//1.解析配置文件获取相机相关配置
	int i = parserIniFile(&gb);
	if(i != 0)
	{
		spdlog::info("Json Parser Error. Please Check!");
		return 0;
	}

    spdlog::info("device info: ");
    spdlog::info("server sip sid: {}", gb.server_id);
    spdlog::info("server ip address: {}", gb.server_ip);
    spdlog::info("server port: {}", gb.server_port);
    spdlog::info("device sip id: {}", gb.device_id);
    spdlog::info("username: {}", gb.username);
    spdlog::info("password: {}", gb.password);
    spdlog::info("manufacture: {}", gb.manufacture);
    spdlog::info("initialize end!");
	
	pthread_create(&revFromIPC, NULL, revIPCSip, (void*)&gb);
	pthread_create(&sendToServer, NULL, sendServerSip, (void*)&gb);

	while(1)
	{
		spdlog::info("main keepalive!");
		sleep(5*60);
	}
#if 0
    auto device = shared_ptr<Device>(
        new Device(gb.server_id, gb.server_ip, gb.server_port, 
            gb.device_id, gb.username, gb.password, gb.device_port, gb.manufacture,
            filepath)
        );
    device->start();
	#endif
}
