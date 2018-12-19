//
// Created by Will on 2018-12-18.
//
#include <stdio.h>
#include <dirent.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif


typedef struct {
    size_t capacity;
    char   **tokens;
    size_t size;
} str_stack_t;

void init_str_stack(str_stack_t *stack, size_t capacity) {
    stack->capacity = capacity;
    stack->tokens   = malloc(sizeof(char *) * capacity);
    stack->size     = 0;
}

void push(str_stack_t *stack, char *item) {
    if (stack->size >= stack->capacity)
        return;
    *(stack->tokens + stack->size) = item;
    stack->size++;
}

char *pop(str_stack_t *stack) {
    if (stack->size < 1)
        return NULL;
    stack->size--;
    char *result = stack->tokens[stack->size];
    stack->tokens[stack->size] = NULL;
    return result;

}

char *top(str_stack_t *stack) {
    if (stack->size < 1)
        return NULL;
    return stack->tokens[stack->size - 1];
}


char **str_split(char *str, char delim, size_t *size);

char *join_tokens(char **tokens);

void print_file(const char *path, char *prefix) {

    DIR *dirp;
    dirp = opendir(path);

    if (dirp == NULL)
        return;

    while (1) {
        struct dirent *direntp;
        direntp = readdir(dirp);
        if (direntp == NULL)
            break;
        else if (direntp->d_name[0] != '.') {
            unsigned short type  = direntp->d_type;
            char           *name = direntp->d_name;
            switch (type) {
                case 4:
//                    printf("%s/%s is a directory\n", path, name);
                    puts("\n");
                    char sub_path[PATH_MAX];
                    strcpy(sub_path, path);
                    strcat(sub_path, "/");
                    strcat(sub_path, name);

                    char new_prefix[PATH_MAX];
                    strcpy(new_prefix, prefix);
                    strcat(new_prefix, "/");
                    strcat(new_prefix, name);
                    print_file(sub_path, new_prefix);
                    break;
                case 8:
                    printf("%s/%s\n", prefix, name);
                    break;
                default:
                    break;
            }
        }
    }
    closedir(dirp);
}

/*
 * `./../install/.././Makefile` => `./../Makefile`
 */
char *parse_path(char *path) {
    char   **tokens;
    size_t token_size = 0;

    tokens = str_split(path, '/', &token_size);

    str_stack_t stack;
    init_str_stack(&stack, 32);

    if (tokens) {
        int i;
        for (i = 0; *(tokens + i); i++) {
            char *cur_token = *(tokens + i);

            if (strcmp(cur_token, "..") != 0)
                push(&stack, cur_token);
            else {
                if (stack.size == 0)
                    push(&stack, cur_token);
                else if (top(&stack)[0] != '.') {
                    pop(&stack);
                } else
                    push(&stack, cur_token);
            }
        }
    }

    printf("stack_size is %lu\n", stack.size);

    if (stack.size > 0)
        return join_tokens(stack.tokens);

    return "WILL";
}

char *join_tokens(char **tokens) {

    char *result;
    result = (char *) malloc((PATH_MAX) * sizeof(char));

    if (tokens) {
        int i;
        for (i = 0; *(tokens + i); i++) {
            char *curr_token = *(tokens + i);
            char *next_token = *(tokens + i + 1);

            if (i == 0) strcpy(result, curr_token);
            else
                strcat(result, curr_token);

            if (next_token)
                strcat(result, "/");
        }
    }

    return result;
}

char *get_path(char *pwd, char *dpath) {
    char   **tokens_pwd;
    char   **tokens_dpath;
    size_t pwd_token_size   = 0;
    size_t dpath_token_size = 0;

    printf("pwd path is %s\n", pwd);
    printf("dpath path is %s\n", dpath);

    tokens_pwd   = str_split(pwd, '/', &pwd_token_size);
    tokens_dpath = str_split(dpath, '/', &dpath_token_size);

    printf("pwd_token_size is %lu\n", pwd_token_size);
    printf("dpath_token_size is %lu\n", dpath_token_size);

    return "will";

//    printf("token_size=[%lu]\n\n", token_size);
//    if (tokens) {
//        int i;
//        for (i = 0; *(tokens + i); i++) {
//            printf("month=[%s]\n", *(tokens + i));
//            free(*(tokens + i));
//        }
//        printf("\n");
//        free(tokens);
//    }

}

//  about string #START#   ////////////////////////////////////////////////////////////////////
char **str_split(char *str, const char delim, size_t *size) {
    printf("str in function `str_split`  is %s\n", str);
//    char   *origin     = str;
    char   **result    = NULL;
    size_t count       = 0;
    char   *last_comma = NULL;
    char   delim_str[2];
    delim_str[0] = delim;
    delim_str[1] = '\0';

    char *tmp = str;
    while (*tmp) {
        if (delim == *tmp) {
            count++;
            last_comma = tmp;
        }
        tmp++;
    }

    /* Add space for trailing token. */
    count += last_comma < (str + strlen(str) - 1);

    /* Add space for terminating null string so caller
       knows where the list of returned strings ends.
       or add int* to tell caller the length of result. */
    count++;

    /* If first char in str equals delim count-- */
    if (delim == *str) count--;

    result = malloc(sizeof(char *) * count);
    if (result) {
        size_t idx    = 0;
        char   *token = strtok(str, delim_str);
        while (token) {
            assert(idx < count);
            *(result + idx++) = strdup(token);
            token = strtok(NULL, delim_str);
        }
        assert(idx == count - 1);
        *(result + idx) = NULL;
        *size           = idx;
    }
    return result;
}
// about string #END#      ////////////////////////////////////////////////////////////////////

#define ngx_cdecl

int ngx_cdecl
main(int argc, char *const *argv) {
//    char dir[PATH_MAX] = {0};
//    int n = readlink("/proc/self/exe", dir, PATH_MAX);
//    printf("PATH_MAX: %d\n", PATH_MAX);
//    printf("readlink return: %d\n", n);
//    printf("dir: %s\n", dir);


    char *root;
    if (argc == 1) {
        root = ".";
    } else {
        root = argv[1];
    }

    printf("The `argc` is: %i\n", argc);

    char op_path[PATH_MAX];
    getcwd(op_path, PATH_MAX); // 获取执行命令时所在的目录 而不是程序所在的目录 如 `/Users/will/github/nginx`
    printf("The current directory is: %s\n", op_path);
    printf("program is: %s \n\n", argv[0]);

    char *dest;
    if (strcmp(root, ".") == 0) {
        dest = op_path;
    } else if (*root == '/') {
        dest = root;
    } else {
        strcat(op_path, "/");
        strcat(op_path, root);
        dest = op_path;
    }

    printf("dest path is %s\n", dest);
    print_file(dest, root);


//    get_path(op_path, strdup("./../../path/path.txt"));

//    char *res = parse_path(strdup("./../../path/path.txt"));
//    char *res = parse_path(strdup("./../install/.././Makefile"));
//    printf("res is %s\n\n", res);

//    char   *path      = strdup("./../../path/path.txt");
//    char   **tokens;
//    size_t token_size = 0;
//    tokens = str_split(op_path, '/', &token_size);
//    tokens = str_split(path, '/', &token_size);
//    printf("token_size=[%lu]\n\n", token_size);
//    if (tokens) {
//        int i;
//        for (i = 0; *(tokens + i); i++) {
//            printf("month=[%s]\n", *(tokens + i));
//            free(*(tokens + i));
//        }
//        printf("\n");
//        free(tokens);
//    }



//    char name[] = "will";
//    printf("size of name is: %lu \n", sizeof(name));
//
//    int null;
//    null = '\0';
//    printf("null is: %i \n", null);


//    char months[] = "JAN,FEB,MAR,APR,MAY,JUN,JUL,AUG,SEP,OCT,NOV,DEC";
//    char **tokens;
//    printf("months=[%s]\n\n", months);
//    size_t token_size = 0;
//    tokens = str_split(months, ',', &token_size);
//    printf("token_size=[%lu]\n\n", token_size);
//    if (tokens) {
//        int i;
//        for (i = 0; *(tokens + i); i++) {
//            printf("month=[%s]\n", *(tokens + i));
//            free(*(tokens + i));
//        }
//        printf("\n");
//        free(tokens);
//    }





    return 0;

//    int count = 3;
//    count += 23 < 54;
//    printf("count is: %i \n", count);

//    print_file(op_path);


//    DIR *dirp;
//    struct dirent *direntp;
//    dirp = opendir(op_path);
//    if (dirp != NULL) {
//        while (1) {
//            direntp = readdir(dirp);
//            if (direntp == NULL)
//                break;
//            else if (direntp->d_name[0] != '.') {
//                unsigned short type = direntp->d_type;
//                printf("file type is %i\n", type);
//                printf("%s\n", direntp->d_name);
//            }
//        }
//        closedir(dirp);
//        return EXIT_SUCCESS;
//    }
//
//    return EXIT_FAILURE;
}
