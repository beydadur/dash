#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void write_dot_header(FILE *file) {
    fprintf(file, "digraph ProcessTree {\n");
}

void write_dot_footer(FILE *file) {
    fprintf(file, "}\n");
}

void parse_and_write_dot(FILE *input, FILE *output) {
    char line[256];
    int current_pid = -1;

    while (fgets(line, sizeof(line), input)) {
        char *current = line; // line üzerinde işlem yapacağımız yardımcı gösterici
        char *token;
        int pid, parent_pid = -1;
        char command[128];

        // Trim leading spaces
        while (*current == ' ')
            current++;

        // Parse PID
        token = strtok(current, " ");
        if (token == NULL)
            continue;

        pid = atoi(token);

        // Parse parent-child relation (indicated by indentation)
        int depth = 0;
        for (char *c = line; *c == ' '; c++) {
            depth++;
        }
        depth /= 2; // Each level is 2 spaces

        if (depth > 0)
            parent_pid = current_pid;

        // Parse command name
        token = strstr(current, "| Command: ");
        if (token) {
            token += strlen("| Command: ");
            sscanf(token, "%127[^\n]", command);
        } else {
            strcpy(command, "Unknown");
        }

        // Write DOT node
        fprintf(output, "    %d [label=\"%s\"];\n", pid, command);

        // Write DOT edge (parent -> child)
        if (parent_pid != -1) {
            fprintf(output, "    %d -> %d;\n", parent_pid, pid);
        }

        current_pid = pid;
    }
}


int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <input_file> <output_file>\n", argv[0]);
        return 1;
    }

    FILE *input = fopen(argv[1], "r");
    if (!input) {
        perror("Failed to open input file");
        return 1;
    }

    FILE *output = fopen(argv[2], "w");
    if (!output) {
        perror("Failed to open output file");
        fclose(input);
        return 1;
    }

    // Write DOT header
    write_dot_header(output);

    // Parse and convert
    parse_and_write_dot(input, output);

    // Write DOT footer
    write_dot_footer(output);

    fclose(input);
    fclose(output);

    printf("DOT file generated: %s\n", argv[2]);
    return 0;
}

