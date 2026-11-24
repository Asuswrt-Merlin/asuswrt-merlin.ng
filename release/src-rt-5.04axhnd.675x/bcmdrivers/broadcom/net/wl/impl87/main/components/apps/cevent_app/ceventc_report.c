/*
 * cevent CLI reporting
 *
 *
 * Copyright (C) 2022, Broadcom. All Rights Reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *
 * <<Broadcom-WL-IPTag/Open:>>
 *
 *
 * $Id:$
 */

#include "ceventc.h"

int
ca_cli_dump_local(ca_cli_t *ctx)
{
	const char * nv_out_file_path = nvram_safe_get("ceventd_out");
	/* large enough for the template plus two full-length paths (CA_FILE_PATH_LEN
	 * each) and both grep filters without truncation */
	char sys_cmd[1024] = "";
	char grep_iface[64] = "";
	char grep_mac[64] = "";

	if (nv_out_file_path && nv_out_file_path[0]) {
		const int pathLen = strnlen(nv_out_file_path, CA_FILE_PATH_LEN);
		if (pathLen > 0 && pathLen < (CA_FILE_PATH_LEN - 4)) { /* -4 to accommodate .bak */
			ca_snprintf(ctx->out_path, CA_FILE_PATH_LEN, nv_out_file_path);
			ca_snprintf(ctx->out_bak_path, sizeof(ctx->out_bak_path),
					"%s.bak", ctx->out_path);

			if (ctx->iface[0]) {
				ca_snprintf(grep_iface, sizeof(grep_iface),
						"grep -i -e %s |", ctx->iface);
			}
			if (ctx->mac[0]) {
				ca_snprintf(grep_mac, sizeof(grep_mac), "grep -i -e %s |",
						ctx->mac);
			}
			/* Header uses the SAME fixed-width columns as the data rows below so
			 * they stay aligned. Numeric columns are sized to their writer-side
			 * types in ceventd_utils.c: Flags is int16 (up to 6 chars incl. sign),
			 * Stts/Rsn/Auth are int32 (up to 11 chars incl. sign).
			 */
			printf("%-28s %12s %-8s %-17s %-6s %-11s %-11s %-11s %-8s %-3s %s\n",
					"TIME(ms)", "TDiff(ms)", "IFace", "STA_MAC_ADDRESS", "Flags",
					"Stts", "Rsn", "Auth", "AT", "Dir", "EVENT");
			ca_snprintf(sys_cmd, sizeof(sys_cmd),
				"bp=0; grep -v TIME.ms %s %s 2>/dev/null | %s %s "
				"while read -r a b c d e f g h i j k rest; do "
				/* split TIME(ms) into seconds (bs) and ms remainder (bm) for display */
				"bs=`expr $b / 1000`; bm=`expr $b %% 1000`; "
				/* TDiff = ms since previous event; first row has no predecessor -> 0 */
				"if [ \"$bp\" -eq 0 ]; then bd=0; else bd=`expr $b - $bp`; fi; "
				/* %% escapes printf in ca_snprintf; shell receives %Y.%m.%d %H:%M:%S and %Z */
				"bt=`date -d @$bs +\"%%Y.%%m.%%d %%H:%%M:%%S\"`; bz=`date -d @$bs +%%Z`; "
				/* insert zero-padded ms between seconds and timezone: 17:14:19.123 CST */
				"ts=`printf \"%%s.%%03d %%s\" \"$bt\" $bm \"$bz\"`; "
				/* same column widths as the header above to keep rows aligned */
				"printf \"%%-28s %%12s %%-8s %%-17s %%-6s %%-11s %%-11s %%-11s %%-8s %%-3s %%s\\n\" "
				"\"$ts\" \"$bd\" \"$c\" \"$d\" \"$e\" \"$f\" \"$g\" \"$h\" \"$i\" \"$j\" \"$k\"; "
				"bp=$b; done",
				ctx->out_path, ctx->out_bak_path, grep_iface, grep_mac);
			system(sys_cmd);
		}
	}

	return BCME_OK;
}
