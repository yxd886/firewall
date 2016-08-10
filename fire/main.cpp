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

#include "firewall.hpp"




int main(int argc, char** argv)
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
    firewall fire;
    firewall_state t;
    t.pass_no=0;
    t.drop_no=0;
    t.match_no=0;

   FILE* f;
  if( (f=fopen("/home/sunmmer/firewall/fire/code.txt","r"))==NULL)
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
	   fire.handle(head,&t);
	  // struct headinfo t;
	  // struct headinfo *hd=&t;
	   //Format(head,hd);
	  // filter_local_out(hd);

  }


    fclose(f);
    printf("pass number: %d\ndrop number: %d\nmatch number:%d\n",t.pass_no,t.drop_no,t.match_no);

}




