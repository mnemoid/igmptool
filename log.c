/*
 * log.c
 *
 *  Created on: Oct 7, 2017
 *      Author: Vladimir Lutsenko
 *
 *  This file is part of igmptool.
 *
 *    igmptool is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *
 *    igmptool is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with igmptool.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include "log.h"

static struct {
	int log_destination;
	int level;
	FILE *log_file;
} log_cfg = {
		.log_destination = LOG_DEST_STDERR,
		.level = LOG_WARNING,
		.log_file = NULL
};

int init_log(int loglevel, char *fp) {
	if(fp == NULL) {
		log_cfg.log_file = stderr;
	}
	else {
		log_cfg.log_file = fopen(fp, "a");
		if(log_cfg.log_file == NULL) {
			printf("Can't open log file! %s\n", strerror(errno));
			return -1;
		}
	}
	log_cfg.level = loglevel;
	return 0;
}

void close_log(void) {
	if(log_cfg.log_file != NULL) {
		fclose(log_cfg.log_file);
	}
	return;
}

void write_log(int loglevel, const char *fmt, ...) {
	va_list args;
	char buffer[LOG_BUFFER_SIZE];
	time_t cur_time = time(NULL);
	struct tm *p = localtime(&cur_time);
	struct timeval tv;
	size_t len;
	FILE *fp;

	/* If loglevel of message > configured loglevel then exit */
	if(loglevel > log_cfg.level)
		return;
	/* Check log destination */
	if(log_cfg.log_destination == LOG_DEST_STDERR || log_cfg.log_destination == LOG_DEST_FILE) {
		if(log_cfg.log_file == NULL) {
			fp = stderr;
		}
		else {
			fp = log_cfg.log_file;
		}

		/* Get current time and date */
		cur_time = time(NULL);
		p = localtime(&cur_time);
		gettimeofday(&tv, NULL);

		/* Write date and time with delimiter */
		len = strftime(buffer, sizeof(buffer), "%b %d %Y %T.", p);
		len += sprintf(buffer+len, "%06d: ", (int)(tv.tv_usec));
		va_start(args, fmt);
		len += vsnprintf(buffer+len, sizeof(buffer)-len-1, fmt, args);
		va_end(args);

		/* Append \n and \0 at the end of message */
		buffer[len] = '\n';
		buffer[len+1] = '\0';
		fprintf(fp, buffer);
		fflush(fp);
	}
	return;
}
