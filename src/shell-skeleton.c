#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <termios.h> // termios, TCSANOW, ECHO, ICANON
#include <unistd.h>
#include <fcntl.h> // for input redirection
#include <sys/stat.h> //for input redirection
#include <dirent.h> // for directory operations 

const char *sysname = "dash";

enum return_codes {
	SUCCESS = 0,
	EXIT = 1,
	UNKNOWN = 2,
};

struct command_t {
	char *name;
	bool background;
	bool auto_complete;
	int arg_count;
	char **args;
	char *redirects[3]; // in/out redirection
	struct command_t *next; // for piping
};

/**
 * Prints a command struct
 * @param struct command_t *
 */
void print_command(struct command_t *command) {
	int i = 0;
	printf("Command: <%s>\n", command->name);
	printf("\tIs Background: %s\n", command->background ? "yes" : "no");
	printf("\tNeeds Auto-complete: %s\n",
		   command->auto_complete ? "yes" : "no");
	printf("\tRedirects:\n");

	for (i = 0; i < 3; i++) {
		printf("\t\t%d: %s\n", i,
			   command->redirects[i] ? command->redirects[i] : "N/A");
	}

	printf("\tArguments (%d):\n", command->arg_count);

	for (i = 0; i < command->arg_count; ++i) {
		printf("\t\tArg %d: %s\n", i, command->args[i]);
	}

	if (command->next) {
		printf("\tPiped to:\n");
		print_command(command->next);
	}
}

/**
 * Release allocated memory of a command
 * @param  command [description]
 * @return         [description]
 */
int free_command(struct command_t *command) {
	if (command->arg_count) {
		for (int i = 0; i < command->arg_count; ++i)
			free(command->args[i]);
		free(command->args);
	}

	for (int i = 0; i < 3; ++i) {
		if (command->redirects[i])
			free(command->redirects[i]);
	}

	if (command->next) {
		free_command(command->next);
		command->next = NULL;
	}

	free(command->name);
	free(command);
	return 0;
}

/**
 * Show the command prompt
 * @return [description]
 */
int show_prompt() {
	char cwd[1024], hostname[1024];
	gethostname(hostname, sizeof(hostname));
	getcwd(cwd, sizeof(cwd));
	printf("%s@%s:%s %s$ ", getenv("USER"), hostname, cwd, sysname);
	return 0;
}

/**
 * Parse a command string into a command struct
 * @param  buf     [description]
 * @param  command [description]
 * @return         0
 */
int parse_command(char *buf, struct command_t *command) {
	const char *splitters = " \t"; // split at whitespace
	int index, len;
	len = strlen(buf);

	// trim left whitespace
	while (len > 0 && strchr(splitters, buf[0]) != NULL) {
		buf++;
		len--;
	}

	while (len > 0 && strchr(splitters, buf[len - 1]) != NULL) {
		// trim right whitespace
		buf[--len] = 0;
	}

	// auto-complete
	if (len > 0 && buf[len - 1] == '?') {
		command->auto_complete = true;
	}

	// background
	if (len > 0 && buf[len - 1] == '&') {
		command->background = true;
	}

	char *pch = strtok(buf, splitters);
	if (pch == NULL) {
		command->name = (char *)malloc(1);
		command->name[0] = 0;
	} else {
		command->name = (char *)malloc(strlen(pch) + 1);
		strcpy(command->name, pch);
	}

	command->args = (char **)malloc(sizeof(char *));

	int redirect_index;
	int arg_index = 0;
	char temp_buf[1024], *arg;

	while (1) {
		// tokenize input on splitters
		pch = strtok(NULL, splitters);
		if (!pch)
			break;
		arg = temp_buf;
		strcpy(arg, pch);
		len = strlen(arg);

		// empty arg, go for next
		if (len == 0) {
			continue;
		}

		// trim left whitespace
		while (len > 0 && strchr(splitters, arg[0]) != NULL) {
			arg++;
			len--;
		}

		// trim right whitespace
		while (len > 0 && strchr(splitters, arg[len - 1]) != NULL) {
			arg[--len] = 0;
		}

		// empty arg, go for next
		if (len == 0) {
			continue;
		}

		// piping to another command
		if (strcmp(arg, "|") == 0) {
			struct command_t *c = malloc(sizeof(struct command_t));
			int l = strlen(pch);
			pch[l] = splitters[0]; // restore strtok termination
			index = 1;
			while (pch[index] == ' ' || pch[index] == '\t')
				index++; // skip whitespaces

			parse_command(pch + index, c);
			pch[l] = 0; // put back strtok termination
			command->next = c;
			continue;
		}

		// background process
		if (strcmp(arg, "&") == 0) {
			// handled before
			continue;
		}

		// handle input redirection
		redirect_index = -1;
		if (arg[0] == '<') {
			redirect_index = 0;
		}

		if (arg[0] == '>') {
			if (len > 1 && arg[1] == '>') {
				redirect_index = 2;
				arg++;
				len--;
			} else {
				redirect_index = 1;
			}
		}

                // fix redirection file name
                // different from source code
                if (redirect_index != -1) { //this is the case when the operator next to file such as <out.txt
                    if (strlen(arg)>1) {
                      command->redirects[redirect_index] = strdup(arg+1);
                    } 
                    else { // if there is a space between them << out.txt
                        pch = strtok(NULL,splitters); 
                        if (pch) {
                            command->redirects[redirect_index] =strdup(pch);
                        }
                        else {
                            printf("there is no file name after redirection\n");
                        }
                    }
                    continue;
                }

		// normal arguments
		if (len > 2 &&
			((arg[0] == '"' && arg[len - 1] == '"') ||
			 (arg[0] == '\'' && arg[len - 1] == '\''))) // quote wrapped arg
		{
			arg[--len] = 0;
			arg++;
		}

		command->args =
			(char **)realloc(command->args, sizeof(char *) * (arg_index + 1));

		command->args[arg_index] = (char *)malloc(len + 1);
		strcpy(command->args[arg_index++], arg);
	}
	command->arg_count = arg_index;

	// increase args size by 2
	command->args = (char **)realloc(
		command->args, sizeof(char *) * (command->arg_count += 2));

	// shift everything forward by 1
	for (int i = command->arg_count - 2; i > 0; --i) {
		command->args[i] = command->args[i - 1];
	}

	// set args[0] as a copy of name
	command->args[0] = strdup(command->name);

	// set args[arg_count-1] (last) to NULL
	command->args[command->arg_count - 1] = NULL;

	return 0;
}

void prompt_backspace() {
	putchar(8); // go back 1
	putchar(' '); // write empty over
	putchar(8); // go back 1 again
}

void handle_auto_complete(char *buf, size_t *index);

/**
 * Prompt a command from the user
 * @param  buf      [description]
 * @param  buf_size [description]
 * @return          [description]
 */
int prompt(struct command_t *command) {
	size_t index = 0;
	char c;
	char buf[4096];
	static char oldbuf[4096];

	// tcgetattr gets the parameters of the current terminal
	// STDIN_FILENO will tell tcgetattr that it should write the settings
	// of stdin to oldt
	static struct termios backup_termios, new_termios;
	tcgetattr(STDIN_FILENO, &backup_termios);
	new_termios = backup_termios;
	// ICANON normally takes care that one line at a time will be processed
	// that means it will return if it sees a "\n" or an EOF or an EOL
	new_termios.c_lflag &=
		~(ICANON |
		  ECHO); // Also disable automatic echo. We manually echo each char.
	// Those new settings will be set to STDIN
	// TCSANOW tells tcsetattr to change attributes immediately.
	tcsetattr(STDIN_FILENO, TCSANOW, &new_termios);

	show_prompt();
	buf[0] = 0;

	while (1) {
		c = getchar();
		// printf("Keycode: %u\n", c); // DEBUG: uncomment for debugging

                // handle tab
                if (c == 9) { // Tab tuşu
                        buf[index] = '\0'; // Şu ana kadar girilen komut
                        handle_auto_complete(buf, &index); // Auto-complete işlevini çağır
                        continue;
                }

		// handle backspace
		if (c == 127) {
			if (index > 0) {
				prompt_backspace();
				index--;
			}
			continue;
		}

		if (c == 27 || c == 91 || c == 66 || c == 67 || c == 68) {
			continue;
		}

		// up arrow
		if (c == 65) {
			while (index > 0) {
				prompt_backspace();
				index--;
			}

			char tmpbuf[4096];
			printf("%s", oldbuf);
			strcpy(tmpbuf, buf);
			strcpy(buf, oldbuf);
			strcpy(oldbuf, tmpbuf);
			index += strlen(buf);
			continue;
		}

		putchar(c); // echo the character
		buf[index++] = c;
		if (index >= sizeof(buf) - 1)
			break;
		if (c == '\n') // enter key
			break;
		if (c == 4) // Ctrl+D
			return EXIT;
	}

	// trim newline from the end
	if (index > 0 && buf[index - 1] == '\n') {
		index--;
	}

	// null terminate string
	buf[index++] = '\0';

	strcpy(oldbuf, buf);

	parse_command(buf, command);

	// print_command(command); // DEBUG: uncomment for debugging

	// restore the old settings
	tcsetattr(STDIN_FILENO, TCSANOW, &backup_termios);
	return SUCCESS;
}


void kuhex(const char *filename, int group_size);
int process_command(struct command_t *command) {
    int r;

    if (strcmp(command->name, "") == 0) {
        return SUCCESS;
    }

    if (strcmp(command->name, "exit") == 0) {
        return EXIT;
    }

    if (strcmp(command->name, "cd") == 0) {
        if (command->arg_count > 1) {
            r = chdir(command->args[1]);
            if (r == -1) {
                printf("-%s: %s: %s\n", sysname, command->name,
                       strerror(errno));
            }
            return SUCCESS;
        } else {
            printf("-%s: cd: missing argument\n", sysname);
            return UNKNOWN;
        }
    }
    
    if (strcmp(command->name, "kuhex") == 0) {
        if (command->arg_count < 3) {
            printf("Usage: kuhex <filename> -g <group_size>\n");
            return UNKNOWN;
        }

        const char *filename = command->args[1];
        int group_size = atoi(command->args[3]); // Group size'ı al
        if (group_size != 1 && group_size != 2 && group_size != 4 && group_size != 8 && group_size != 16) {
            printf("Invalid group size. Valid options are 1, 2, 4, 8, 16.\n");
            return UNKNOWN;
        }

        kuhex(filename, group_size); // Kuhex işlevini çağır
        return SUCCESS;
    }
    
    if (strcmp(command->name, "psvis") == 0) {
        if (command->arg_count < 3) {
            printf("Usage: psvis <PID> <output_file>\n");
            return UNKNOWN;
        }

        const char *pid_str = command->args[1];
        const char *output_file = command->args[2];

        // Modülü yükle
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "sudo insmod /home/doga/Masaüstü/comp-304-project-1-fall-2024-coderduo/module/psvis.ko pid=%s", pid_str);

        if (system(cmd) != 0) {
            printf("Failed to load psvis module.\n");
            return UNKNOWN;
        }

        // `/proc/psvis` çıktısını kaydet
        snprintf(cmd, sizeof(cmd), "cat /proc/psvis > %s", output_file);
        system(cmd);

        // Modülü kaldır
        system("sudo rmmod psvis");

        printf("Process tree saved to %s\n", output_file);
        return SUCCESS;
    }



    int pipe_fd[2];
    pid_t pid;
    struct command_t *current_command = command;
    int input_fd = STDIN_FILENO; // Start with standard input

    while (current_command != NULL) {
        // Create a pipe if there is a next command
        if (current_command->next != NULL) {
            if (pipe(pipe_fd) < 0) {
                perror("pipe failed");
                return UNKNOWN;
            }
        }

        pid = fork();
        if (pid == 0) {
            // Child process

            // Handle input redirection or pipe input
            if (current_command->redirects[0]) {
                int fd = open(current_command->redirects[0], O_RDONLY);
                if (fd < 0) {
                    perror("Input redirection failed");
                    exit(UNKNOWN);
                }
                dup2(fd, STDIN_FILENO);
                close(fd);
            } else if (input_fd != STDIN_FILENO) {
                dup2(input_fd, STDIN_FILENO);
                close(input_fd);
            }

            // Handle output redirection or pipe output
            if (current_command->redirects[1]) {
                int fd = open(current_command->redirects[1], O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (fd < 0) {
                    perror("Output redirection failed");
                    exit(UNKNOWN);
                }
                dup2(fd, STDOUT_FILENO);
                close(fd);
            } else if (current_command->redirects[2]) {
                int fd = open(current_command->redirects[2], O_WRONLY | O_CREAT | O_APPEND, 0644);
                if (fd < 0) {
                    perror("Append redirection failed");
                    exit(UNKNOWN);
                }
                dup2(fd, STDOUT_FILENO);
                close(fd);
            } else if (current_command->next != NULL) {
                dup2(pipe_fd[1], STDOUT_FILENO);
                close(pipe_fd[1]);
            }

            // Close unused pipe ends in the child
            if (current_command->next != NULL) {
                close(pipe_fd[0]);
            }

            char *path_env = getenv("PATH");
            if (path_env == NULL) {
                fprintf(stderr, "PATH environment variable not found.\n");
                exit(UNKNOWN);
            }

            char *paths = strdup(path_env);
            char *path = strtok(paths, ":");
            char exec_path[1024];
            int found = 0;

            while (path != NULL) {
                snprintf(exec_path, sizeof(exec_path), "%s/%s", path, current_command->name);
                if (access(exec_path, X_OK) == 0) {
                    found = 1;
                    break;
                }
                path = strtok(NULL, ":");
            }

            if (found) {
                current_command->args[current_command->arg_count] = NULL; 
                execv(exec_path, current_command->args);
                perror("execv failed");
            } else {
                printf("-%s: %s: command not found\n", sysname, current_command->name);
            }

            free(paths);
            exit(UNKNOWN);
        } else if (pid > 0) {
            // Parent process
            if (input_fd != STDIN_FILENO) {
                close(input_fd);
            }
            if (current_command->next != NULL) {
                close(pipe_fd[1]);
                input_fd = pipe_fd[0];
            }

            if (!current_command->background) {
                int status;
                waitpid(pid, &status, 0);
            } else {
                printf("Process running in background with PID: %d\n", pid);
            }
        } else {
            perror("fork failed");
            return UNKNOWN;
        }

        current_command = current_command->next;
    }

    return SUCCESS;
}

// Function for autocomplete
#include <dirent.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

void handle_auto_complete(char *buf, size_t *index) {
    DIR *dir;
    struct dirent *entry;
    char partial[4096] = {0}; // Kullanıcının girdiği kısmı tutmak için
    char *last_space;
    char *match = NULL;
    int match_count = 0;

    // Kullanıcının yazdığı kısmı (son komut) al
    last_space = strrchr(buf, ' '); // Son boşluğu bul
    if (last_space) {
        strcpy(partial, last_space + 1); // Son boşluktan sonrasını al
    } else {
        strcpy(partial, buf); // Hiç boşluk yoksa tüm girdiyi al
    }

    // Bulunduğun dizini aç
    dir = opendir(".");
    if (!dir) {
        perror("opendir failed");
        return;
    }

    printf("\nAuto-complete options:\n");

    // Dizindeki her bir dosyayı kontrol et
    while ((entry = readdir(dir)) != NULL) {
        // Dosyanın adını al ve kontrol et
        struct stat entry_stat;
        stat(entry->d_name, &entry_stat);

        // Kullanıcının girdiği kısmı eşleştir
        if (strncmp(entry->d_name, partial, strlen(partial)) == 0) {
            // Seçeneği yazdır
            printf("%s%s\n", entry->d_name, S_ISDIR(entry_stat.st_mode) ? "/" : "");
            match_count++;

            // Tek bir eşleşmeyi kaydet
            if (match_count == 1) {
                match = strdup(entry->d_name);
            } else {
                free(match);
                match = NULL; // Birden fazla eşleşme varsa tamamlamayı devre dışı bırak
            }
        }
    }
    closedir(dir);

    // Tek eşleşme varsa otomatik olarak tamamla
    if (match && match_count == 1) {
        if (last_space) {
            // "cd " gibi bir prefix varsa tamamla
            snprintf(buf + (last_space - buf) + 1, 4096 - (last_space - buf) - 1, "%s", match);
        } else {
            // Prefix yoksa direkt tamamla
            snprintf(buf, 4096, "%s", match);
        }
        *index = strlen(buf); // Yeni buffer uzunluğunu ayarla
        free(match);
    }

    // Prompt'u yeniden yazdır
    show_prompt();
    printf("%s", buf);
}

//for kuhex
#include <ctype.h>

void kuhex(const char *filename, int group_size) {
    FILE *file = fopen(filename, "rb"); // Dosyayı binary modunda aç
    if (!file) {
        perror("Failed to open file");
        return;
    }

    unsigned char buffer[16]; // Her satır için 16 baytlık okuma tamponu
    size_t bytes_read;
    size_t offset = 0; // Dosya konumu

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        // Offset yazdır
        printf("%08lx: ", offset);

        // Hexadecimal gruplama
        for (size_t i = 0; i < sizeof(buffer); i++) {
            if (i < bytes_read) {
                if (i % group_size == 0 && i > 0)
                    printf(" "); // Grup arasına boşluk ekle
                printf("%02x", buffer[i]);
            } else {
                // Eksik byte'lar için boşluk bırak
                printf("   ");
            }
        }

        // ASCII temsili
        printf("  ");
        for (size_t i = 0; i < bytes_read; i++) {
            if (isprint(buffer[i])) {
                printf("%c", buffer[i]);
            } else {
                printf(".");
            }
        }
        printf("\n");

        offset += bytes_read; // Offset'i güncelle
    }

    fclose(file);
}


int process_command(struct command_t *command);

int main() {
	while (1) {
		struct command_t *command = malloc(sizeof(struct command_t));

		// set all bytes to 0
		memset(command, 0, sizeof(struct command_t));

		int code;
		code = prompt(command);
		if (code == EXIT) {
			break;
		}

		code = process_command(command);
		if (code == EXIT) {
			break;
		}

		free_command(command);
	}

	printf("\n");
	return 0;
}

