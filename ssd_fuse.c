/*
  FUSE ssd: FUSE ioctl example
  Copyright (C) 2008       SUSE Linux Products GmbH
  Copyright (C) 2008       Tejun Heo <teheo@suse.de>
  This program can be distributed under the terms of the GNU GPLv2.
  See the file COPYING.
*/
#define FUSE_USE_VERSION 35

#include <fuse.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include "ssd_fuse_header.h"

#define SSD_NAME       "ssd_file"
#define NAND_LBA_NUM (NAND_SIZE_KB * 1024 / 512)



enum
{
    SSD_NONE,
    SSD_ROOT,
    SSD_FILE,
};


// in page (pca)
static size_t physic_size;
// in page (lba)
static size_t logic_size;
static size_t host_write_size;
static size_t nand_write_size;

typedef union pca_rule PCA_RULE;
union pca_rule
{
    unsigned int pca;
    struct
    {
        unsigned int lba : 16;
        unsigned int nand: 16;
    } fields;
};

PCA_RULE curr_pca;

unsigned int* L2P;

typedef enum gbgState{
    CLEAN = 0,  // unused
    VALID = 1,  // in use
    INVALID = 2 // garbage
} gbgState;

gbgState* states;



static int ssd_resize(size_t new_size)
{
    printf("===ssd_resize===\n");
    //set logic size to new_size
    if (new_size >= LOGICAL_NAND_NUM * NAND_SIZE_KB * 1024  )
    {
        return -ENOMEM;
    }
    else
    {
        logic_size = new_size;
        return 0;
    }

}

static int ssd_expand(size_t new_size)
{
    printf("===ssd_expand===\n");
    //logic must less logic limit

    if (new_size > logic_size)
    {
        return ssd_resize(new_size);
    }

    return 0;
}

static int nand_read(char* buf, int pca)
{
    printf("==========nand_read==========\n");
    char nand_name[100];
    FILE* fptr;

    PCA_RULE my_pca;
    my_pca.pca = pca;
    snprintf(nand_name, 100, "%s/nand_%d", NAND_LOCATION, my_pca.fields.nand);

    //read
    if ( (fptr = fopen(nand_name, "r") ))
    {
        printf("===open file===\n");
        fseek( fptr, my_pca.fields.lba * 512, SEEK_SET );
        fread(buf, 1, 512, fptr);
        fclose(fptr);
    }
    else
    {
        printf("open file fail at nand read pca = %d\n", pca);
        return -EINVAL;
    }
    return 512;
}
static int nand_write(const char* buf, int pca)
{
    printf("==========nand_write==========\n");
    char nand_name[100];
    FILE* fptr;

    PCA_RULE my_pca;
    my_pca.pca = pca;
    snprintf(nand_name, 100, "%s/nand_%d", NAND_LOCATION, my_pca.fields.nand);

    //write
    if ( (fptr = fopen(nand_name, "r+")))
    {
        printf("===open file===\n");
        
        fseek( fptr, my_pca.fields.lba * 512, SEEK_SET );
        fwrite(buf, 1, 512, fptr);
        fclose(fptr);
        physic_size ++;
    }
    else
    {
        printf("open file fail at nand (%s) write pca = %d, return %d\n", nand_name, pca, -EINVAL);
        return -EINVAL;
    }

    nand_write_size += 512;

    return 512;
}
static int nand_erase(int nand)
{
    printf("==========nand_erase==========\n");
    char nand_name[100];
	int found = 0;
    FILE* fptr;

    snprintf(nand_name, 100, "%s/nand_%d", NAND_LOCATION, nand);

    //erase
    if ( (fptr = fopen(nand_name, "w")))
    {
        found = 1;
        fclose(fptr);
    }
    else
    {
        printf("open file fail at nand (%s) erase nand = %d, return %d\n", nand_name, nand, -EINVAL);
        return -EINVAL;
    }


	if (found == 0)
	{
		printf("nand erase not found\n");
		return -EINVAL;
	}
    
    for(int i = nand * NAND_LBA_NUM; i < (nand + 1) * NAND_LBA_NUM; i++){
        if(states[i] != CLEAN){
            physic_size --;
        }
        states[i] = CLEAN;
    }
    
    printf("nand erase %d pass\n", nand);
    return 1;
}
static unsigned int get_next_pca(int black)
{
    printf("==========get_next_pca==========\n");
    if (curr_pca.pca == INVALID_PCA)
    {
        //init
        printf("Initial PCA = lba 0, nand 0\n");
        curr_pca.pca = 0;
        return curr_pca.pca;
    }
    else if (curr_pca.pca == FULL_PCA)
        {
            //full ssd, no pca can allocate
        printf("==========No new PCA==========\n");
        return FULL_PCA;
    }

    int found = 0;
    curr_pca.pca = INVALID_PCA;
    
    for(int i = 0; i < 8 && !found; i++){
        if(black != -1 && black == i)continue;

        for(int j = 0; j < 20; j++){
            if(states[i * 20 + j] == CLEAN){
                found = 1;
                curr_pca.fields.lba = j;
                curr_pca.fields.nand = i;
                states[i * 20 + j] = VALID;
                break;
            }
        }
    }
    if ( curr_pca.pca == INVALID_PCA )
    {
        printf("No new PCA\n");
        curr_pca.pca = FULL_PCA;
        return FULL_PCA;
    }
    else
    {
        printf("PCA = lba %d, nand %d\n", curr_pca.fields.lba, curr_pca.fields.nand);
        return curr_pca.pca;
    }
    
}
static int select_victim(){
    int validCount[PHYSICAL_NAND_NUM], invalidCount[PHYSICAL_NAND_NUM];
    memset(validCount, 0, PHYSICAL_NAND_NUM * sizeof(int));
    memset(invalidCount, 0, PHYSICAL_NAND_NUM * sizeof(int));

    for(int i = 0; i < 8; i++){
        for(int j = 0; j < 20; j++) {
            if(states[i * 20 + j] == VALID)
                validCount[i]++;
            if(states[i * 20 + j] == INVALID)
                invalidCount[i]++;
        }
    }

    int vic = 0, max = invalidCount[0];
    for(int i = 1; i < 8; i++){
        if(invalidCount[i] > max) {
            max = invalidCount[i];
            vic = i;
        }
        else if(invalidCount[i] == max){
            if(validCount[i] < validCount[vic])
                vic = i;
        }
    }
    printf("victim: %d\n", vic);
    return vic;
}


static int ftl_gc()
{
    int victim = select_victim();
    char temp[512];
    PCA_RULE pca;
    PCA_RULE newPca;
    printf("gc triggered\n");

    for(int i = 0; i < LOGICAL_NAND_NUM * NAND_SIZE_KB * 1024 / 512; ++i){
        pca.pca = L2P[i];
        if(pca.fields.nand == victim){
            nand_read(temp, pca.pca);
            newPca.pca = get_next_pca(victim);
            if(newPca.pca == INVALID_PCA){
                return -EINVAL;
            }
            nand_write(temp, newPca.pca);
            L2P[i] = newPca.pca;
        }
    }

    nand_erase(victim);

    return 0;
}
static int ftl_read(char* buf, size_t lba)
{
    printf("==========ftl_read==========\n");
    PCA_RULE pca;

	pca.pca = L2P[lba];
	if (pca.pca == INVALID_PCA) {
	    //non write data, return 0
	    return 0;
	}
	else {
	    return nand_read(buf, pca.pca);
	}
}
static int ftl_write(const char* buf, size_t lba_rnage, size_t lba) //512 byte data
{
    printf("==========ftl_write==========\n");
    while(physic_size >= 135){
        ftl_gc();
    }
    /*  only simple write, need to consider other cases  */
    PCA_RULE pca;
    PCA_RULE oldPca;
    pca.pca = get_next_pca(-1);

    if (nand_write(buf, pca.pca) > 0)
    {
        oldPca.pca = L2P[lba];
        if(oldPca.pca != INVALID_PCA) states[oldPca.fields.nand * 20 + oldPca.fields.lba] = INVALID;
        L2P[lba] = pca.pca;
        return 512 ;
    }
    else
    {
        printf(" --> Write fail !!!\n");
        return -EINVAL;
    }
}



static int ssd_file_type(const char* path)
{
    printf("===ssd_file_type===\n");
    printf("path:%s\n",path);
    if (strcmp(path, "/") == 0)
    {
        return SSD_ROOT;
    }
    if (strcmp(path, "/" SSD_NAME) == 0)
    {
        return SSD_FILE;
    }
    return SSD_NONE;
}
static int ssd_getattr(const char* path, struct stat* stbuf,
                       struct fuse_file_info* fi)
{
    printf("==========ssd_getattr==========\n");
    (void) fi;
    stbuf->st_uid = getuid();
    stbuf->st_gid = getgid();
    stbuf->st_atime = stbuf->st_mtime = time(NULL);
    switch (ssd_file_type(path))
    {
        case SSD_ROOT:
            stbuf->st_mode = S_IFDIR | 0755;
            stbuf->st_nlink = 2;
            break;
        case SSD_FILE:
            stbuf->st_mode = S_IFREG | 0644;
            stbuf->st_nlink = 1;
            stbuf->st_size = logic_size;
            break;
        case SSD_NONE:
            return -ENOENT;
    }
    return 0;
}


static int ssd_open(const char* path, struct fuse_file_info* fi)
{
    printf("==========ssd_open==========\n");
    (void) fi;
    if (ssd_file_type(path) != SSD_NONE)
    {
        return 0;
    }
    return -ENOENT;
}


static int ssd_do_read(char* buf, size_t size, off_t offset)
{
    printf("==========ssd_do_read==========\n");
    //printf("size:%ld  offset:%ld  buf:\n%s\n", size, offset, buf);

    int tmp_lba, tmp_lba_range, rst ;
    char* tmp_buf;

    printf("logic_size:%ld\n", logic_size);
    // off limit
    if ((offset ) >= logic_size)
    {
        return 0;
    }
    if ( size > logic_size - offset)
    {
        //is valid data section
        size = logic_size - offset;
    }


    tmp_lba = offset / 512;
	tmp_lba_range = (offset + size - 1) / 512 - (tmp_lba) + 1;
    tmp_buf = calloc(tmp_lba_range * 512, sizeof(char));

    for (int i = 0; i < tmp_lba_range; i++) {
        rst = ftl_read(tmp_buf + i * 512, tmp_lba + i);

        if ( rst == 0)
        {
            //is zero, read unwrite data
            printf("Reading unwrite data.\n");
            memset(tmp_buf + i * 512, 0, 512);
        }
        else if (rst < 0 )
        {
            free(tmp_buf);
            return rst;
        }
    }

    memcpy(buf, tmp_buf + offset % 512, size);
    //printf("size:%ld  offset:%ld  buf:\n%s\n", size, offset, buf);

    free(tmp_buf);
    return size;
}
static int ssd_read(const char* path, char* buf, size_t size,
                    off_t offset, struct fuse_file_info* fi)
{
    printf("==========ssd_read==========\n");
    (void) fi;
    if (ssd_file_type(path) != SSD_FILE)
    {
        return -EINVAL;
    }
    return ssd_do_read(buf, size, offset);
}


static int ssd_do_write(const char* buf, size_t size, off_t offset)
{
    printf("==========ssd_do_write==========\n");
    printf("size:%ld  offset:%ld  buf:\n%s\n", size, offset, buf);

    char tempBuf[512];
    int init_lba, lba_range, process_size;
    int idx, curr_size, remain_size, rst;

    host_write_size += size;
    if (ssd_expand(offset + size) != 0)
    {
        return -ENOMEM;
    }

    memset(tempBuf,0,512);
    init_lba = offset / 512;
    lba_range = (offset + size - 1) / 512 - (init_lba) + 1;

    process_size = 0;
    remain_size = size;
    curr_size = 0;
    for (idx = 0; idx < lba_range; idx++)
    {
        memset(tempBuf,0,512);
        ftl_read(tempBuf,init_lba+idx);
        if(idx == 0&&offset%512){
            if(remain_size<512-(offset%512)){
                memcpy(tempBuf+(offset%512),buf,remain_size);
                rst = ftl_write(tempBuf,1,init_lba+idx);
                if(rst == 0) return -ENOMEM;
                if(rst < 0) return rst;

                remain_size = 0;
                break;
            }
            else{
                memcpy(tempBuf+(offset%512),buf,512 - (offset%512));
                rst = ftl_write(tempBuf,1,init_lba+idx);
                if(rst == 0) return -ENOMEM;
                if(rst < 0) return rst;

                remain_size -= 512-(offset%512);
                curr_size +=512-(offset%512);
                process_size +=512-(offset%512);
                offset += 512-(offset%512);
            }
            continue;
        }
        else if(remain_size<512){
            memcpy(tempBuf,buf+process_size,remain_size);
            rst = ftl_write(tempBuf,1,init_lba+idx);
        }
        else{
            rst = ftl_write(buf + process_size,1,init_lba+idx);
        }
        if(rst == 0) return -ENOMEM;
        if(rst < 0) return rst;

        curr_size +=512;
        remain_size -=512;
        process_size +=512;
        offset +=512;
    }
    while(physic_size >= 135){
        ftl_gc();
    }
    return size;

    /*int init_lba, lba_range;//, process_size;
    int lbaIdx, srcIdx, remain_size, rst;

    host_write_size += size;
    if (ssd_expand(offset + size) != 0)
    {
        return -ENOMEM;
    }

    init_lba = offset / 512;
    lba_range = (offset + size - 1) / 512 - (init_lba) + 1;

    char dstBuf[512];

    //process_size = 0;
    remain_size = size;
    srcIdx = 0;
    for (lbaIdx = 0; lbaIdx < lba_range; lbaIdx++)
    {
        memset(dstBuf, 0, 512);

        rst = ftl_read(dstBuf, init_lba + lbaIdx);
        if (rst == 0)
        {
            //is zero, read unwrite data
            printf("Reading unwrite data.\n");
            memset(dstBuf + lbaIdx * 512, 0, 512);
        }
        else if (rst < 0 )
            return rst;

        printf("dstBuf:%s\n",dstBuf);

        // if can fit into this lba (final)
        if (remain_size < (512 - (offset % 512)))
            memcpy(dstBuf + (offset%512), buf + srcIdx, remain_size);
        // if over this lba
        else
            memcpy(dstBuf + (offset%512), buf + srcIdx, 512 - (offset % 512));

        rst = ftl_write(dstBuf, 1, init_lba + lbaIdx);
        if (rst < 0)
            return rst;

        remain_size -= (512 - (offset % 512));
        srcIdx += (512 - (offset % 512));
        offset += (512 - (offset % 512));
    }

    while(physic_size >= 135){
        ftl_gc();
    }
    return size;*/
}
static int ssd_write(const char* path, const char* buf, size_t size,
                     off_t offset, struct fuse_file_info* fi)
{
    printf("==========ssd_write==========\n");

    (void) fi;
    if (ssd_file_type(path) != SSD_FILE)
    {
        return -EINVAL;
    }
    return ssd_do_write(buf, size, offset);
}


static int ssd_truncate(const char* path, off_t size,
                        struct fuse_file_info* fi)
{
    printf("==========ssd_truncate==========\n");
    (void) fi;
    if (ssd_file_type(path) != SSD_FILE)
    {
        return -EINVAL;
    }

    return ssd_resize(size);
}


static int ssd_readdir(const char* path, void* buf, fuse_fill_dir_t filler,
                       off_t offset, struct fuse_file_info* fi,
                       enum fuse_readdir_flags flags)
{
    printf("==========ssd_readdir==========\n");
    (void) fi;
    (void) offset;
    (void) flags;
    if (ssd_file_type(path) != SSD_ROOT)
    {
        return -ENOENT;
    }
    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);
    filler(buf, SSD_NAME, NULL, 0, 0);
    return 0;
}


static int ssd_ioctl(const char* path, unsigned int cmd, void* arg,
                     struct fuse_file_info* fi, unsigned int flags, void* data)
{
    printf("==========ssd_ioctl==========\n");

    if (ssd_file_type(path) != SSD_FILE)
    {
        return -EINVAL;
    }
    if (flags & FUSE_IOCTL_COMPAT)
    {
        return -ENOSYS;
    }
    switch (cmd)
    {
        case SSD_GET_LOGIC_SIZE:
            *(size_t*)data = logic_size;
            printf(" --> logic size: %ld\n", logic_size);
            return 0;
        case SSD_GET_PHYSIC_SIZE:
            *(size_t*)data = physic_size;
            printf(" --> physic size: %ld\n", physic_size);
            return 0;
        case SSD_GET_WA:
            *(double*)data = (double)nand_write_size / (double)host_write_size;
            return 0;
    }
    return -EINVAL;
}


static const struct fuse_operations ssd_oper =
{
    .getattr        = ssd_getattr,
    .readdir        = ssd_readdir,
    .truncate       = ssd_truncate,
    .open           = ssd_open,
    .read           = ssd_read,
    .write          = ssd_write,
    .ioctl          = ssd_ioctl,
};



int main(int argc, char* argv[])
{
    printf("===============main STARTS!!!===============\n");
    int idx;
    char nand_name[100];
    physic_size = 0;
    logic_size = 0;
	nand_write_size = 0;
	host_write_size = 0;
    curr_pca.pca = INVALID_PCA;
    L2P = malloc(LOGICAL_NAND_NUM * NAND_SIZE_KB * 1024 / 512 * sizeof(int));
    memset(L2P, INVALID_PCA, sizeof(int)*LOGICAL_NAND_NUM * NAND_SIZE_KB * 1024 / 512);
    states = calloc(sizeof(gbgState), PHYSICAL_NAND_NUM * NAND_SIZE_KB * 1024 / 512);

    //create nand file
    for (idx = 0; idx < PHYSICAL_NAND_NUM; idx++)
    {
        FILE* fptr;
        snprintf(nand_name, 100, "%s/nand_%d", NAND_LOCATION, idx);
        fptr = fopen(nand_name, "w");
        if (fptr == NULL)
        {
            printf("open fail\n");
        }
        fclose(fptr);
    }
    return fuse_main(argc, argv, &ssd_oper, NULL);
}
