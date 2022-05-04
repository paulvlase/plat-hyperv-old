/* SPDX-License-Identifier: BSD-3-Clause */
/**
 * Virtio IDs
 *
 * This header is BSD licensed so anyone can use the definitions to implement
 * compatible drivers/servers.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of IBM nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL IBM OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/**
 * Taken and modified from Linux Kernel.
 * include/uapi/linux/vmbus_ids.h
 *
 * Commit-id:dbaf0624ffa5
 */
#ifndef __PLAT_DRV_VMBUS_IDS_H
#define __PLAT_DRV_VMBUS_IDS_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus __ */

#define VMBUS_ID_INVALID       0 /* Invalid device (Reserved) */
#define VMBUS_ID_NET		1 /* vmbus net */
#define VMBUS_ID_BLOCK		2 /* vmbus block */
#define VMBUS_ID_CONSOLE	3 /* vmbus console */
#define VMBUS_ID_RNG		4 /* vmbus rng */
#define VMBUS_ID_BALLOON	5 /* vmbus balloon */
#define VMBUS_ID_RPMSG		7 /* vmbus remote processor messaging */
#define VMBUS_ID_SCSI		8 /* vmbus scsi */
#define VMBUS_ID_9P		9 /* 9p vmbus console */
#define VMBUS_ID_RPROC_SERIAL 11 /* vmbus remoteproc serial link */
#define VMBUS_ID_CAIF	       12 /* vmbus caif */
#define VMBUS_ID_GPU          16 /* vmbus GPU */
#define VMBUS_ID_INPUT        18 /* vmbus input */
#define VMBUS_ID_VSOCK        19 /* vmbus vsock transport */
#define VMBUS_ID_CRYPTO       20 /* vmbus crypto */

#ifdef __cplusplus
}
#endif /* __cplusplus __ */

#endif /* __PLAT_DRV_VMBUS_IDS_H */
