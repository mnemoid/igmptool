/*
 * log.h
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

#ifndef LOG_H_
#define LOG_H_

#define LOG_BUFFER_SIZE		1024

#define LOG_DEST_STDERR		1
#define LOG_DEST_FILE		2
#define LOG_DEST_SYSLOG		4

#define	LOG_EMERG	0	/* system is unusable */
#define	LOG_ALERT	1	/* action must be taken immediately */
#define	LOG_CRIT	2	/* critical conditions */
#define	LOG_ERR		3	/* error conditions */
#define	LOG_WARNING	4	/* warning conditions */
#define	LOG_NOTICE	5	/* normal but significant condition */
#define	LOG_INFO	6	/* informational */
#define	LOG_DEBUG	7	/* debug-level messages */

int init_log(int, char *);
void close_log(void);
size_t write_log(int, const char *, ...);

#endif /* LOG_H_ */
