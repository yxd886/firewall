/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>
#include <rte_config.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>

#include <string>
#include <iostream>

#include "caf/all.hpp"
#include "firewall.hpp"

using std::endl;
using std::string;
using std::cout;
using std::pair;
using namespace caf;

using start_atom = atom_constant<atom("start")>;

static int
lcore_hello(__attribute__((unused)) void *arg)
{
	unsigned lcore_id;
	lcore_id = rte_lcore_id();
	printf("hello from core %u\n", lcore_id);
	return 0;
}
class firewall : public event_based_actor{
public:
  firewall(actor_config& cfg):event_based_actor(cfg)
{
   firest.match_no=0;
   firest.drop_no=0;
   firest.pass_no=0;
   firest.current_pass=0;
   FILE*fp=fopen("/home/net/nf-actor/actor-framework/examples/nfactor/rule.txt","r");
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
      &rp->dport,
      &rp->protocol,
      &rp->action);
      cout<<"rule push back"<<endl;
      cout<<rp->saddr.addr<<" "<<rp->protocol<<" "<<rp->sport<<endl;
     rules.push_back(r);

   }
   cout<<"begin to close the rule file !"<<endl;
   fclose(fp);
   cout<<"close the rule file successfully !"<<endl;

}

    behavior make_behavior() override {
        //return firewall_fun(this);
     // send(this, step_atom::value);
    // philosophers start to think after receiving {think}
     // become(normal_task());
    //  become(keep_behavior, reconnecting());
    return behavior{

      [=](start_atom) {
          start();

      }

    };
    
  
  
}



  void handle(char* packet,struct firewall_state* p)
  {
    struct headinfo t;
    struct headinfo* hd=&t;
    cout<<"begin to format"<<endl;
    Format(packet,hd);
    cout<<"format packet completed"<<endl;
    filter_local_out(hd);
    p->match_no=firest.match_no;
    p->pass_no=firest.pass_no;
    p->current_pass=firest.current_pass;
    p->drop_no=firest.drop_no;


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
    FILE*fp=fopen("/home/net/nf-actor/actor-framework/examples/nfactor/firewall_log.txt","a+");
    if(fp==NULL)
    {
      cout<<"open file error"<<endl;
      getchar();
    }
    cout<<"begin to enter loop"<<endl;
    for(ptr=rules.begin();ptr!=rules.end();ptr++){

      //gettimeofday(&timeval,NULL);
      //local_time = (u32)(timeval.tv_sec + (8 * 60 * 60));
      //rtc_time_to_tm(local_time, &tm);
      cout<<" enter loop"<<endl;
      t = time(NULL);
      cout<<" get time 1"<<endl;
      local = localtime(&t);
      cout<<" get time 2"<<endl;
      strftime(strtime, 64, "%Y-%m-%d %H:%M:%S", local);
      cout<<" get time 3"<<endl;
      match = false;
      match = (ptr->saddr.addr == ANY_ADDR ? true : CompareID_with_mask(ptr->saddr.addr,s_addr,ptr->saddr.mask));
      if(!match){

        cout<<" sadd no match continue"<<endl;
        continue;
      }
      match = (ptr->daddr.addr == ANY_ADDR ? true : CompareID_with_mask(ptr->daddr.addr,d_addr,ptr->daddr.mask));
      if(!match){
        cout<<" dadd no match continue"<<endl;
        continue;
      }
      match = (ptr->protocol == ANY_PROTOCOL) ? true : (ptr->protocol == protocol);
      if(!match){
        cout<<" proto no match continue"<<endl;
        continue;
      }
      match = (ptr->sport == ANY_PORT) ? true : (ptr->sport == s_port);
      if(!match){
        cout<<" sport no match continue"<<endl;
        continue;
      }
      match = (ptr->dport == ANY_PORT) ? true : (ptr->dport == d_port);
      if(!match){
        cout<<" dport no match continue"<<endl;
        continue;
      }
    //  match = ptr->action ? 0 : 1;

      if(match){

        cout<<"packet matches"<<endl;
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

void start()
{
     //char** a;
    //a[1]=(char*)malloc(sizeof(pkt1));a[1]=(char*)pkt1;

  struct ether_header *m_pEthhdr;
  struct iphdr *m_pIphdr; 
    char tmp1[2000];
    memset(tmp1,0,sizeof(tmp1));
    char *head=tmp1;
    char *packet=tmp1+34;
    uint16_t len;
   FILE* f;
  if( (f=fopen("/home/net/nf-actor/actor-framework/examples/nfactor/code.txt","r"))==NULL)
    {
    printf("OPen File failure\n");
    }

   while (!feof(f))
   {
     cout<<"begin to read code"<<endl;
     fread(head,34,1,f);
     cout<<"read head ok"<<endl;
     m_pEthhdr=(struct ether_header *)head;
     m_pIphdr=(struct iphdr *)(head+sizeof(struct ether_header));
     len = ntohs(m_pIphdr->tot_len);
     printf("length: %x\n",len);
     cout<<"begin to read  packet"<<endl;
     fread(packet,len-20,1,f);
     cout<<"read  packet ok"<<endl;
     cout<<"put packet to the hander"<<endl;
     handle(head,&firest);
    // struct headinfo t;
    // struct headinfo *hd=&t;
     //Format(head,hd);
    // filter_local_out(hd);

  }


    fclose(f);
    printf("pass number: %d\ndrop number: %d\nmatch number:%d\n",t.pass_no,t.drop_no,t.match_no);

}

struct firewall_state firest;
vector <struct rule> rules;

};

void caf_main(actor_system& system) {
	int ret;
	unsigned lcore_id;
	char c[] = {"./build/bin/hellodpdk"};
	char* t = c;
	ret = rte_eal_init(1, &t);
	if (ret < 0)
		rte_panic("Cannot init EAL\n");
	/* call lcore_hello() on every slave lcore */
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		rte_eal_remote_launch(lcore_hello, NULL, lcore_id);
	}

	/* call it on master lcore too */
	lcore_hello(NULL);

	rte_eal_mp_wait_lcore();

	// our CAF environment
  auto fire=system.spawn<firewall>();
  auon_send(fire,start_atom::value);
}

CAF_MAIN()