#include <string>
#include "spdlog/spdlog.h"
#include "cxxopts.h"
#include "device.h"
#include "cJSON.h"
#include <pthread.h>
#include <unistd.h>
#include "SipServer.h"

using namespace std;

#define JSON_FILE_LENG          (200 * 1024)                                    //JSON�ļ���С
#define MAX_PATH          260

pthread_t revFromIPC; //�������IPC��GBЭ���߳�
pthread_t sendToServer; //��Server��ע��GBЭ���߳�

typedef struct GBParams
{
	string server_id;// = "34070000002000000001";//����ƽ̨��ID��wvp��sip.idֵ��
    string server_ip;// = "192.168.50.100";//����ƽ̨��IP��wvp��sip.ip��
    int server_port;// = 5061;//����ƽ̨�Ķ˿ںţ�wvp��sip.port)
    string device_id;// = "34030000002000000001";//�豸ID�������¼��豸������ƽ̨ʱ����ı��
    string device_domain;// = "3403000000";//�豸��
    string device_ip;// = "192.168.50.130";//����������豸��IP��wvp��sip.ip��
    int device_port;// = 5069;//�˷������ļ����˿�
    string device_num;// = "31011500991320000046";//�豸��ţ��˷����������ͨ�����
    string username;// = "admin";//�˷��������û������룬�豣֤�¼�����server�ͼ���ƽ̨��ͬ
    string password;// = "zx123456";
    string manufacture;// = "LYY";//�������,�����ⶨ��
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

//��json�ļ���ȡ���������Ϣ
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
	
	//��ȡ�����¼��������
	cJSON* deal  = cJSON_GetObjectItem(root, "deal");
	cJSON* userName  = cJSON_GetObjectItem(root, "userName");
	cJSON* userPwd  = cJSON_GetObjectItem(root, "userPwd");

	gb->username = userName->valuestring;
	gb->password = userPwd->valuestring;
	

	//��ȡplatform��Ϣ������Ҫ�������ϼ�ƽ̨����wvp������ƽ̨������Ϣ
	cJSON* platform = cJSON_GetObjectItem(root, "platform");
	cJSON* platform_id = cJSON_GetObjectItem(platform, "platform_id");
	cJSON* platform_port = cJSON_GetObjectItem(platform, "platform_port");
	cJSON* platform_ip = cJSON_GetObjectItem(platform, "platform_ip");

	gb->server_id = platform_id->valuestring;
	gb->server_port = platform_port->valueint;
	gb->server_ip = platform_ip->valuestring;
	spdlog::info("server_port : {}",gb->server_port);

	//��ȡ����ƽ̨��Ϣ�������¼���IPC����������ƽ̨
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

	//��ȡ���豸�ı�ţ��������Զ���
	cJSON* local_number = cJSON_GetObjectItem(local, "local_number");
	gb->device_num = local_number->valuestring;

#if 0
	cJSON* cameraInf = cJSON_GetObjectItem(root, "cameraInf");
	cJSON* camera = cJSON_GetObjectItem(cameraInf, "camera");

	g_liveVideoParams.cameraNum = cJSON_GetArraySize(camera);										//�������

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
		memcpy(p->sipId, camera_sip_id->valuestring, strlen(camera_sip_id->valuestring)>MAX_PATH?MAX_PATH:strlen(camera_sip_id->valuestring));//��ȡ����ͷID
		p->recvPort = camera_recv_port->valueint;

		memcpy(p->UserPwd, userPwd->valuestring, strlen(userPwd->valuestring)>MAX_PATH?MAX_PATH:strlen(userPwd->valuestring));//��ȡ����ͷ����
		memcpy(p->UserName, userName->valuestring, strlen(userName->valuestring)>MAX_PATH?MAX_PATH:strlen(userName->valuestring));//��ȡ����ͷ�û���

		printf("UserPwd : %s, userName : %s, ini Path : %s\n", p->UserPwd, p->UserName, strIniPath.c_str());
	}

	g_liveVideoParams.gb28181Param.SN = 1;
	g_liveVideoParams.gb28181Param.call_id = -1;
	g_liveVideoParams.gb28181Param.dialog_id = -1;
	g_liveVideoParams.gb28181Param.registerOk = 0;
#endif
	spdlog::info("���������ļ����");

	fclose(fp);
	free(buf);
	return 0;
}


int main(int argc, const char* argv[]) {

	gbParams gb;
	//1.���������ļ���ȡ����������
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
