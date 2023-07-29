//
//  vnode.h
//  kfd
//
//  Created by Seo Hyun-gyu on 2023/07/29.
//

#include <stdio.h>

uint64_t getVnodeAtPath(char* filename);
uint64_t findRootVnode(void);

uint64_t funVnodeHide(char* filename);
uint64_t funVnodeChown(char* filename, uid_t uid, gid_t gid);
uint64_t funVnodeChmod(char* filename, mode_t mode);
uint64_t funVnodeRedirectFolder(char* to, char* from);
uint64_t funVnodeOverwriteFile(char* to);
