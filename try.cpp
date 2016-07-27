/*
 * main.cpp
 *
 *  Created on: 27 Jul, 2016
 *      Author: sunmmer
 */

/*************************************************************************
    > File Name: hook.c
    > Author: yxd
    > Mail: 1359434736@qq.com
    > Created Time: 2016年02月22日 星期一 11时59分57秒
 ************************************************************************/

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <time.h>
#include <iostream>
#include <fstream>
#include <string>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <vector>
#include <sys/time.h>
#include <deque>
#include <set>
#include <map>
#include <list>
#include <asm-generic/int-ll64.h>


typedef short Bool;
#define true 1
#define false 0

#define SRC 0
#define DEST 1

#define PERMIT 1
#define REJECT 0

#define ANY_ADDR 0
#define ANY_PORT 0xffff
#define ANY_PROTOCOL 0xff
#define ANY_TIME(tm) (tm.valid == 0)

#define MASK_IP(x, mask) (x & (0xffffffff << (!mask ? 0 : (32 - mask))))


using namespace std;
 struct rule{
     struct{
          uint32_t addr;        //IP地址
          uint8_t mask;         //掩码
     }saddr, daddr;             //源IP地址，目的IP地址
     uint16_t sport, dport;     //源端口，目的端口
     __u8 protocol;             //协议类型
     int action;               //动作

};


struct headinfo{
    struct ether_header *m_pEthhdr;
    struct iphdr *m_pIphdr;
    struct tcphdr *m_pTcphdr;
    struct udphdr *m_pUdphdr;
    __u8 protocol;
};


struct firewall_state{
	int match_no;
	int drop_no;
	int pass_no;
	bool current_pass;

};

class firewall{
public:
	firewall()
{
   firest.match_no=0;
   firest.drop_no=0;
   firest.pass_no=0;
   firest.current_pass=0;
   FILE*fp=fopen("/home/sunmmer/firewall/rule.txt","r");
   char saddr[200];
   memset(saddr,0,sizeof(saddr));
   char daddr[200];
   memset(daddr,0,sizeof(daddr));
   if(fp==NULL)
   {
	   cout<<"open file error!"<<endl;

   }
   struct rule r;
   struct rule* rp=&r;
   cout<<"begin to read rules"<<endl;
   while(!feof(fp))
   {
	   fscanf(fp,"%hhu.%hhu.%hhu.%hhu /%u:%u, %hhu.%hhu.%hhu.%hhu /%u:%u, %u, %d",
			(unsigned char *)&rp->saddr.addr,
			((unsigned char *)&rp->saddr.addr)+1,
			((unsigned char *)&rp->saddr.addr)+2,
			((unsigned char *)&rp->saddr.addr)+3,
			&rp->saddr.mask,
			&rp->sport,
			(unsigned char *)&rp->daddr.addr,
			(unsigned char *)&rp->daddr.addr+1,
			(unsigned char *)&rp->daddr.addr+2,
			(unsigned char *)&rp->daddr.addr+3,
			&rp->daddr.mask,
			&rp->sport,
			&rp->protocol,
			&rp->action);
	    cout<<"rule push back"<<endl;
	    cout<<rp->saddr.addr<<" "<<rp->protocol<<endl;
	   rules.push_back(r);

   }
   fclose(fp);

}

	void handle(char* packet,struct firewall_state* p)
	{
		struct headinfo t;
		struct headinfo* hd=&t;
		Format(packet,hd);
		filter_local_out(hd);
		p=&firest;


	}

private:


		void Format(char* packet,struct headinfo* hd)
	{
	       hd->m_pEthhdr = (struct ether_header*)packet;
	       hd->m_pIphdr = (struct iphdr*)(packet + sizeof(struct ether_header));
	       if(hd->m_pIphdr->protocol==IPPROTO_TCP)
	       {
	    	   hd->m_pTcphdr = (struct tcphdr*)(packet + sizeof(struct ether_header)+(hd->m_pIphdr->ihl)*4);
	    	   hd->m_pUdphdr=NULL;
	       }else if(hd->m_pIphdr->protocol==IPPROTO_UDP)
	       {
		       hd->m_pTcphdr = NULL;
		       hd->m_pUdphdr=(struct udphdr*)(packet + sizeof(struct ether_header)+(hd->m_pIphdr->ihl)*4);
	       }else
	       {
		       hd->m_pTcphdr = NULL;
		       hd->m_pUdphdr=NULL;
	       }

	       hd->protocol =  hd->m_pIphdr->protocol;
	    return;
	}


	Bool CompareID_with_mask(uint32_t addr1, uint32_t addr2, uint8_t mask){
		uint32_t addr1_temp, addr2_temp;
		Bool flag = false;
		addr1_temp = ntohl(addr1);
		addr2_temp = ntohl(addr2);

		addr1_temp = MASK_IP(addr1_temp, mask);
		addr2_temp = MASK_IP(addr2_temp, mask);

		flag = (addr1_temp == addr2_temp);


		return flag;
	}




	void filter_local_out(struct headinfo *hd){
		uint32_t s_addr, d_addr;
		__u8 protocol;
		uint16_t s_port, d_port;
		char strtime[128]= {0};
		time_t t;
		tm* local;
		Bool match = false;
		Bool flag = false;
		protocol = hd->protocol;
		s_addr = hd->m_pIphdr->saddr;
		d_addr = hd->m_pIphdr->daddr;
		s_port = GetPort(hd, SRC);
		d_port = GetPort(hd, DEST);
		vector<struct rule>::iterator ptr;
		FILE*fp=fopen("/home/sunmmer/firewall/log.txt","wt");
		for(ptr=rules.begin();ptr!=rules.end();ptr++){

			//gettimeofday(&timeval,NULL);
			//local_time = (u32)(timeval.tv_sec + (8 * 60 * 60));
			//rtc_time_to_tm(local_time, &tm);
			t = time(NULL);
			local = localtime(&t);
			strftime(strtime, 64, "%Y-%m-%d %H:%M:%S", local);
			match = false;
			match = (ptr->saddr.addr == ANY_ADDR ? true : CompareID_with_mask(ptr->saddr.addr,s_addr,ptr->saddr.mask));
			if(!match){

				continue;
			}
			match = (ptr->daddr.addr == ANY_ADDR ? true : CompareID_with_mask(ptr->daddr.addr,d_addr,ptr->daddr.mask));
			if(!match){

				continue;
			}
			match = (ptr->protocol == ANY_PROTOCOL) ? true : (ptr->protocol == protocol);
			if(!match){

				continue;
			}
			match = (ptr->sport == ANY_PORT) ? true : (ptr->sport == s_port);
			if(!match){

				continue;
			}
			match = (ptr->dport == ANY_PORT) ? true : (ptr->dport == d_port);
			if(!match){

				continue;
			}
		//	match = ptr->action ? 0 : 1;

			if(match){


				flag = ptr->action?false:true;
				++firest.match_no;
					    fprintf(fp,
					    "time@[%s] %hhu.%hhu.%hhu.%hhu/%u:%u to %hhu.%hhu.%hhu.%hhu/%u:%u, protocol: %u, action: %s\n",
						strtime,
						((unsigned char *)&ptr->saddr.addr)[0],
						((unsigned char *)&ptr->saddr.addr)[1],
						((unsigned char *)&ptr->saddr.addr)[2],
						((unsigned char *)&ptr->saddr.addr)[3],
						ptr->saddr.mask, ptr->sport,
						((unsigned char *)&ptr->daddr.addr)[0],
						((unsigned char *)&ptr->daddr.addr)[1],
						((unsigned char *)&ptr->daddr.addr)[2],
						((unsigned char *)&ptr->daddr.addr)[3],
						ptr->daddr.mask, ptr->dport,
						ptr->protocol,
						ptr->action ? "Permit" : "Reject");

				break;
			}
			else{
				flag = false;
				break;
			}
		}//loop for match rule
		fclose(fp);
		if(flag){
			firest.drop_no++;
			firest.current_pass=false;
		}else{
			firest.pass_no++;
			firest.current_pass=true;
		}

	}
	 uint16_t GetPort(struct headinfo *hd, int flag){
	 	uint16_t port = ANY_PORT;
	 	switch(hd->m_pIphdr->protocol){
	 		case IPPROTO_TCP:
	 			if(flag == SRC)
	 				port = ntohs(hd->m_pTcphdr->source);
	 			else if(flag == DEST)
	 				port = ntohs(hd->m_pTcphdr->dest);
	 			break;
	 		case IPPROTO_UDP:
	 			if(flag == SRC)
	 				port = ntohs(hd->m_pUdphdr->source);
	 			else if(flag == DEST)
	 				port = ntohs(hd->m_pUdphdr->dest);
	 			break;
	 		default:
	 			port = ANY_PORT;
	 	}
	 	return port;
	 }



struct firewall_state firest;
vector <struct rule> rules;

};

int main(int argc, char** argv)
{
     //char** a;
    //a[1]=(char*)malloc(sizeof(pkt1));a[1]=(char*)pkt1;

struct rule a;
struct rule* rp=&a;

   FILE* f;
  if( (f=fopen("/home/sunmmer/firewall/rule.txt","rt"))==NULL)
	  {
	  cout<<"error"<<endl;
	  }

   	   fscanf(f,"%hhu.%hhu.%hhu.%hhu /%u:%u, %hhu.%hhu.%hhu.%hhu /%u:%u, %u, %d",
			(unsigned char *)&rp->saddr.addr,
			((unsigned char *)&rp->saddr.addr)+1,
			((unsigned char *)&rp->saddr.addr)+2,
			((unsigned char *)&rp->saddr.addr)+3,
			&rp->saddr.mask,
			&rp->sport,
			(unsigned char *)&rp->daddr.addr,
			(unsigned char *)&rp->daddr.addr+1,
			(unsigned char *)&rp->daddr.addr+2,
			(unsigned char *)&rp->daddr.addr+3,
			&rp->daddr.mask,
			&rp->sport,
			&rp->protocol,
			&rp->action);
   	   cout<<rp->saddr.addr<<endl;
   	   cout<<rp->sport<<endl;


    fclose(f);

}




