#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "ole_common.h"
#define MAX_MSAT_IDS 100
static unsigned char *pbuf = NULL;
static long buf_len = 0;
static int32_t msat_ids[MAX_MSAT_IDS];
static int msat_ids_used = 0;
static int32_t root_start_block = -1;
static int32_t root_block_size = -1;
static int32_t max_block_no = -1;
static uint32_t max_did = 0;

static void print_hex_buff (unsigned char *start, unsigned char *end, int hex_output)
{
	unsigned char *src = start;
	if (!hex_output) {
		return;
	}
	printf ("[clam hex:\n");
	while (start < end) {
		printf ("%.2x ", *start);
		if(!((start - src+1)%16))
			printf("\n");
		start++;
	}
	printf ("]\n");
}
char *get_property_name(char *name, int size)
{
	int i, j;
	char *newname;

	if (*name == 0 || size <= 0 || size > 64) {
		return NULL;
	}

	newname = (char *)malloc(size*7);
	if (!newname) {
		return NULL;
	}
	j=0;
	/* size-2 to ignore trailing NULL */
	for (i=0 ; i < size-2; i+=2) {
		if((!(name[i]&0x80)) && isprint(name[i])) {
			newname[j++] = tolower(name[i]);
		} else {
			if (name[i] < 10 && name[i] >= 0) {
				newname[j++] = '_';
				newname[j++] = name[i] + '0';
			}
			else {
				const uint16_t x = (((uint16_t)name[i]) << 8) | name[i+1];
				newname[j++] = '_';
				newname[j++] = 'a'+((x&0xF));
				newname[j++] = 'a'+((x>>4)&0xF);
				newname[j++] = 'a'+((x>>8)&0xF);
				newname[j++] = 'a'+(((uint32_t)x>>16)&0xF);
				newname[j++] = 'a'+(((uint32_t)x>>24)&0xF);
			}
			newname[j++] = '_';
		}
	}
	newname[j] = '\0';
	if (strlen(newname) == 0) {
		free(newname);
		return NULL;
	}
	return newname;
}
static void print_ole_property(ole_property_t *property)
{
	char spam[128], *buf;
	if (property->name_size > 64) {
		printf("[err name len: %d]\n", property->name_size);
		return;
	}
	buf = get_property_name(property->name, property->name_size);
	snprintf(spam, sizeof(spam), "OLE2: %s ", buf ? buf : "<noname>");
	spam[sizeof(spam)-1]='\0';
	if (buf) free(buf);
	switch (property->type) {
		case 2:
			strncat(spam, " [file] ", sizeof(spam) - 1 - strlen(spam));
			break;
		case 1:
			strncat(spam, " [dir ] ", sizeof(spam) - 1 - strlen(spam));
			break;
		case 5:
			strncat(spam, " [root] ", sizeof(spam) - 1 - strlen(spam));
			break;
		default:
			strncat(spam, " [unkn] ", sizeof(spam) - 1 - strlen(spam));
	}
	spam[sizeof(spam)-1]='\0';
	switch (property->color) {
		case 0:
			strncat(spam, " r  ", sizeof(spam) - 1 - strlen(spam));
			break;
		case 1:
			strncat(spam, " b  ", sizeof(spam) - 1 - strlen(spam));
			break;
		default:
			strncat(spam, " u  ", sizeof(spam) - 1 - strlen(spam));
	}
	spam[sizeof(spam)-1]='\0';
	printf("%s size:0x%.8x flags:0x%.8x,start_block:%d\n", spam, property->size, property->user_flags, property->start_block);
}
static void print_ole_header(ole_header_t *hdr)
{
	int i;

	if (!hdr) {
		return;
	}
	printf("\nMagic:\t\t\t0x");
	for (i=0 ; i<8; i++) {
		printf("%x", hdr->magic[i]);
	}
	printf("\n");

	printf("CLSID:\t\t\t{");
	for (i=0 ; i<16; i++) {
		printf("%x ", hdr->clsid[i]);
	}
	printf("}\n");

	printf("Minor version:\t\t0x%x\n", hdr->minor_version);
	printf("DLL version:\t\t0x%x\n", hdr->dll_version);
	printf("Byte Order:\t\t%d\n", hdr->byte_order);
	printf("Big Block Size:\t\t%i\n", hdr->log2_big_block_size);
	printf("Small Block Size:\t%i\n", hdr->log2_small_block_size);
	printf("SAT count:\t\t%d\n", hdr->bat_count);
	printf("Prop start:\t\t%d\n", hdr->prop_start);
	printf("SSAT cutoff:\t\t%d\n", hdr->sbat_cutoff);
	printf("SSAT start:\t\t%d\n", hdr->sbat_start);
	printf("SSAT block count:\t%d\n", hdr->sbat_block_count);
	printf("MSAT start:\t\t%d\n", hdr->xbat_start);
	printf("MSAT block count:\t%d\n\n", hdr->xbat_count);

	return;
}
void init_msat_ids()
{
	//msat_ids_used = 0;
}
void add2msat_id_chain(int32_t msat_id)
{
	if(msat_ids_used >= MAX_MSAT_IDS)
		return;

	msat_ids[msat_ids_used++] = msat_id;
}
typedef struct sat_tag{
	unsigned char buf[512];
}sat_t;
static sat_t *psat = NULL;
static int sat_used = 0;
void add2sat(long offset)
{
	psat = realloc(psat, (sat_used+1)*sizeof(sat_t));
	assert(psat);

	memcpy((unsigned char *)psat->buf+sat_used*sizeof(sat_t), pbuf+offset, 512);
	sat_used++;
	//assert(*(int32_t *)psat->buf == 0xfffffffd); //must be marked as `SAT_ID:-3`
	//print_hex_buff(psat->buf, psat->buf+512, 1);
}
void construct_sat()
{
	int i;
	long offset;

	for(i=0;i<msat_ids_used;i++){
		offset = (msat_ids[i]+1)*512;
		if(offset >= buf_len)
			exit(1);
		add2sat(offset);
	}
}
void print_sat()
{
	int i,j;
	for(i=0;i<sat_used;i++){
#ifdef DEBUG
	printf("[sat:\n");
#endif
		for(j=0;j<128;j++){
#ifdef DEBUG
			printf("%d ", *(int32_t*)(((psat+i)->buf)+j*sizeof(int32_t)));
#endif
			if(*(int32_t*)(((psat+i)->buf)+j*sizeof(int32_t)) > max_block_no)
				exit(1);
		}
#ifdef DEBUG
	printf("\n]\n");
#endif
	}
}
typedef struct ssat_tag{
	unsigned char buf[512];
}ssat_t;
static ssat_t *pssat = NULL;
static int ssat_used = 0;
void add2ssat(long offset)
{
	pssat = realloc(pssat, (ssat_used+1)*sizeof(ssat_t));
	assert(pssat);

	memcpy((unsigned char*)pssat->buf+ssat_used*sizeof(ssat_t), (void*)(pbuf+offset), 512);
	ssat_used++;
}
void construct_ssat(ole_header_t *pheader)
{
	int i,j;
	long offset;
	int32_t ssat_no;

	assert(pheader);
	ssat_no = pheader->sbat_start;
	for(i=0;i<sat_used;i++){
		for(j=1;j<=128;j++){
			if(ssat_no == -2)
				break;
			offset = (ssat_no+1)*512;
			add2ssat(offset);
			ssat_no = *((int32_t *)psat->buf + ssat_no);
			//printf("ssat_no:%d\n", ssat_no);
		}
	}
}
void print_ssat()
{
	int i,j;
	ssat_t *p;

	for(i=0;i<ssat_used;i++){
#ifdef DEBUG
	printf("[ssat:\n");
#endif
		for(j=0;j<128;j++){
#ifdef DEBUG
			printf("%d ", *(int32_t*)(((pssat+i)->buf)+j*sizeof(int32_t)));
#endif
			if(*(int32_t*)(((pssat+i)->buf)+j*sizeof(int32_t)) > max_block_no)
				exit(1);
		}
#ifdef DEBUG
	printf("]\n");
#endif
	}
}
typedef struct dir_tag{
	unsigned char buf[512];
}dir_t;
static dir_t *pdir = NULL;
static int dir_used = 0;
void add2dir(long offset)
{
	pdir = realloc(pdir, (dir_used+1)*sizeof(dir_t));
	assert(pdir);

	memcpy((unsigned char*)pdir->buf+dir_used*sizeof(dir_t), (void*)(pbuf+offset), 512);
	//print_hex_buff(pdir->buf+dir_used*sizeof(dir_t), pdir->buf+dir_used*sizeof(dir_t)+512, 1);
	dir_used++;
}
void construct_dir(ole_header_t *pheader)
{
	int i,j;
	long offset;
	int32_t dir_no;

	assert(pheader);
	dir_no = pheader->prop_start;
	for(i=0;i<sat_used;i++){
		for(j=1;j<=128;j++){
			if(dir_no == -2)
				goto abort;
			offset = (dir_no+1)*512;
			add2dir(offset);
			dir_no = *((int32_t *)psat->buf + dir_no);
			//printf("dir_no:%d\n", dir_no);
		}
	}

abort:
	//print_hex_buff(pdir->buf, pdir->buf+512, 1);
	return;
}
typedef enum at_tag{
	SAT = 0,
	SSAT = 1
}at_t;
typedef struct stream_chain_tag{
	at_t at_type;
	int32_t *pchain;
	uint32_t chain_num;
	uint32_t size;
	int did;
	char path_name[128];
}stream_chain_t;
static stream_chain_t *pstream_chain = NULL;
static int stream_chain_used = 0;
static unsigned char cur_path[128];
void printstream_chain(stream_chain_t *pstream)
{
	int i,j;
	stream_chain_t *p=pstream;

	for(i=0;i<stream_chain_used;i++){
		printf("%s,stream:%s,size:%d,chain_num:%d\n", p->at_type==SSAT?"SSAT":"SAT", p->path_name, p->size, p->chain_num);
		for(j=0;j<p->chain_num;j++){
			printf("%d ", p->pchain[j]);
		}
		p++;
		printf("\n");
	}
}
void add2stream_chain(ole_header_t *pheader, ole_property_t *pprop, int did)
{
	stream_chain_t *ps;
	int32_t cutoff = pheader->sbat_cutoff;
	int32_t block_no = pprop->start_block;
	int is_ssat;
	int i,tmp;
#define MAX_BLOCKS 500
	int32_t blocks[MAX_BLOCKS]; 
	int blocks_used = 0;
	char *name;

	pstream_chain = realloc(pstream_chain, (stream_chain_used+1)*sizeof(stream_chain_t));
	assert(pstream_chain);

	ps = pstream_chain+stream_chain_used;
	is_ssat = pprop->size < cutoff ? 1 : 0;
	ps->at_type = is_ssat ? SSAT : SAT;
	ps->size    = pprop->size;
	ps->did		= did;
	name = get_property_name(pprop->name, pprop->name_size);
	if(name){
		ps->path_name[0] = '\0';
		strncpy(ps->path_name, cur_path, sizeof(ps->path_name));
		strncat(ps->path_name, name, sizeof(ps->path_name));
		free(name);
		name = NULL;
		//printf("path_name:%s\n", ps->path_name);
	}
	tmp = (ps->size+1)/512;
	for(i=0;i<tmp;i++){
		if(block_no == -2)
			break;
		if(block_no < 0 || block_no > max_block_no)
			exit(1);		
		blocks[blocks_used] = block_no;
		if(blocks_used++ >= MAX_BLOCKS){
			printf("blocks used overflow!\n");
			break;
		}
		//:TODO
		//printf("block_no:%d,is_ssat:%d,%d\n", block_no, is_ssat, block_no/128);
		if(is_ssat)
			block_no = *(int32_t*)((pssat+block_no/128)->buf+sizeof(int32_t)*(block_no%128));
		else
			block_no = *(int32_t*)((psat+block_no/128)->buf+(sizeof(int32_t)*(block_no%128)));
	}
	ps->chain_num = blocks_used;
	if(blocks_used > 0){
		ps->pchain = malloc(sizeof(int32_t)*blocks_used);
		assert(ps->pchain);
		memcpy(ps->pchain, blocks, blocks_used*sizeof(int32_t));
	}
	//printf("ps:%p,ps->path_name:%s,ps->chain_num:%d,chain0:%d,chain1:%d\n", ps,ps->path_name, ps->chain_num, ps->pchain[0],ps->pchain[1]);
	stream_chain_used += 1;
}
typedef struct{
	uint32_t prev;
	uint32_t next;
	uint32_t child;
	char *name;
}did_entry_t;
#define MAX_ENTRIES 200
static did_entry_t did_e[MAX_ENTRIES];
static did_e_used = 0;
void add2did_entry(ole_property_t *pprop, int did)
{
	uint32_t prev, next, child;
	did_entry_t *p;

	assert(pprop);
	assert(did >= 0 && did < MAX_ENTRIES);
	if(did_e_used >= MAX_ENTRIES){
		printf("did entries overflow!\n");
		return;
	}
	prev = pprop->prev;
	next = pprop->next;
	child = pprop->child;
	p = &did_e[did];
	p->prev = prev;
	p->next = next;
	p->child = child;
	p->name = get_property_name(pprop->name, pprop->name_size); //remember to free
	if(!p->name){
		p->name = malloc(7);
		assert(p->name);
		strncpy(p->name, "noname", 6);
	}
	did_e_used++;
}
void print_did_ent()
{
	int i;
	did_entry_t *p;

	for(i=0;i<did_e_used;i++){
		p = did_e+i;
		printf("%d.%s prev=%d,next=%d,child=%d\n", i, p->name, p->prev, p->next, p->child);
	}
}
static char pwd[128]="";
static char fullname[128]="";
void traverse_did_ent(did_entry_t *pp)
{
	size_t len;
	if(!pp)
		return;

	if(pp->prev >= 0 && pp->prev <= max_did)
		traverse_did_ent(did_e+pp->prev);
	if(pp->next >= 0 && pp->next <= max_did){
		traverse_did_ent(did_e+pp->next);
	}
	if(pp->child >= 0 && pp->child <= max_did){
		len = strlen(pwd);
		strncat(pwd, pp->name, sizeof(pwd));
		strncat(pwd, "/", sizeof(pwd));
		printf("pwd:%s\n", pwd);
		traverse_did_ent(did_e+pp->child);
		pwd[len] = '\0';
	}
	if(pp->child == -1){
		strncpy(fullname, pwd, sizeof(fullname));
		strncat(fullname, pp->name, sizeof(fullname));
		printf("fullname:%s,max_did=%d\n", fullname, max_did);
	}
}
void construct_stream_chain(ole_header_t *pheader)
{
	long offset;
	int i,j;
	unsigned char *p;
	ole_property_t *prop;
	uint32_t cutoff;
	uint32_t cur_did = 0;
	char *name;
   
	assert(pheader);
	cutoff = pheader->sbat_cutoff;

	printf("dir_used:%d,size_prop:%d\n", dir_used, sizeof(ole_property_t));
	for(i=0;i<dir_used;i++){
		p = pdir[i].buf;
		for(j=1;j<=4;j++){
			//print_ole_property((ole_property_t*)p);
			prop = (ole_property_t*)p;
			switch(prop->type){ /* 1=dir 2=file 5=root */
				case 2:
					cur_did++;
					max_did = cur_did;
					add2did_entry(prop, cur_did);
					//printf("prev:%d,next:%d,child:%d\n", prop->prev, prop->next, prop->child);
					add2stream_chain(pheader, prop, cur_did);
					break;
				case 1:
					cur_did++;
					max_did = cur_did;
					add2did_entry(prop, cur_did);
					name = get_property_name(prop->name, prop->name_size);
					//printf("dir,%s\n",name);
					//printf("prev:%d,next:%d,child:%d\n", prop->prev, prop->next, prop->child);
					break;
				case 5:
					assert(i==0&&j==1);
					cur_did = 0;
					add2did_entry(prop, cur_did);
					root_start_block = prop->start_block;
					root_block_size = prop->size;
					printf("root,start_block:%d,size:%d\n", prop->start_block, prop->size);
					//printf("prev:%d,next:%d,child:%d\n", prop->prev, prop->next, prop->child);
					break;
				default:
					printf("unkown type\n");
					break;
			}
			p = p+sizeof(ole_property_t);
		}
	}
#ifdef DEBUG
	print_did_ent();
	traverse_did_ent(did_e);
#endif
}
void read_sat()
{
	ole_header_t ole_header;
	int i;
	int32_t msat_id;
	unsigned char *p;

	memcpy(&ole_header, pbuf, 512);
	max_block_no = (buf_len - 512) / (1 << ole_header.log2_small_block_size);
	printf("max_block_no:%d,sbat_start:%d,xbat_start:%d\n", max_block_no, ole_header.sbat_start, ole_header.xbat_start);
	if(ole_header.sbat_start >= max_block_no || ole_header.xbat_start >= max_block_no)
		exit(1);
	if(ole_header.log2_big_block_size != 9 || ole_header.log2_small_block_size != 6 || ole_header.sbat_cutoff != 4096){
		printf("dont support!\n");
		exit(1);
	}
	//print_ole_header(&ole_header);
	init_msat_ids();
	//construct msat-id-chain
	//from mast
	p = (unsigned char*)&ole_header + 0x4c;
	for(i=0;i<ole_header.bat_count;i++){
		msat_id = *(int32_t*)p;
		p = p+sizeof(int32_t);
		printf("msat id:%d\n", msat_id);
		if(msat_id == -1)
			break;
		if(msat_id < 0 || msat_id >= max_block_no)
			exit(1);
		add2msat_id_chain(msat_id);
	}
	//from others
	msat_id = ole_header.xbat_start;
	for(i=0;i<ole_header.xbat_count;i++){
		if(msat_id == -1)
			break;
		add2msat_id_chain(msat_id);
		msat_id = *(int32_t*)(pbuf+(msat_id+1)*512);
	}
	
	//construct sat
	construct_sat();
	print_sat();
	construct_ssat(&ole_header);
	print_ssat();
	construct_dir(&ole_header);
	construct_stream_chain(&ole_header);
#ifdef DEBUG
	printstream_chain(pstream_chain);
#endif
}
void read_file(int argc, char **argv)
{
	unsigned char magic_id[] = { 0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1};

	if(argc < 2)
		exit(1);

	FILE *fp = fopen(argv[1], "rb");
	assert(fp);
	fseek(fp, 0, SEEK_END);
	long fl = ftell(fp);
	buf_len = fl;
	rewind(fp);
	pbuf = malloc(fl);
	assert(pbuf);
	long read;
	unsigned char*pbuftmp = pbuf;
	while(fl > 0){
		read = (fl > 512) ? 512 : fl;
		fread(pbuftmp, read, 1, fp);
		fl -= read;
		pbuftmp += read;
	}
	if(memcmp(magic_id, pbuf, sizeof(magic_id)))
		exit(1);

	return;
}
int main(int argc, char **argv)
{
	read_file(argc, argv);
	read_sat();
	//many frees---------
}
