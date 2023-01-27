#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include <strings.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>

#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <math.h>

#include <arpa/inet.h>

#include <netdb.h>

#define SPACE 1
#define QUOATATIONS_MARKS 2
#define PARANTHESIS 2

#define OK 1
#define ERROR 2

enum op_comands {
    REGISTER,
    LOGIN,
    LIST,
    SEND,
    FETCH,
    LOGOUT,
};

char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


// Funkcia ktora vypise napovedu programu na stdout
void print_help(){
    
    char *help_msg = 
        "usage: client [ <option> ... ] <command> [<args>] ...\n"
        "\n"
        "<option> is one of\n"
        "\n"
        "   -a <addr>, --address <addr>\n"
        "       Server hostname or address to connect to\n"
        "   -p <port>, --port <port>\n"
        "       Server port to connect to\n"
        "   --help, -h\n"
        "       Show this help\n"
        "   --\n"
        "       Do not treat any remaining argument as a switch (at this level)\n"
        "\n"
        "Multiple single-letter switches can be combined after\n"
        "one `-`. For example, `-h-` is the same as `-h --`.\n"
        "Supported commands:\n"
        "   register <username> <password>\n"
        "   login <username> <password>\n"
        "   list\n"
        "   send <recipient> <subject> <body>\n"
        "   fetch <id>\n"
        "   logout\n";

        printf("%s", help_msg);

}

// Funkcia ktora skontroluje prihlasenie
bool check_logged_in()
{
    FILE *fPtr;

    if ((fPtr = fopen("login-token", "r")) == NULL)
    {
        printf("Not logged in\n");
        return false;
    }

    fclose(fPtr);
    return true;
}

// Funkcia ktora nacita login-token zo suboru
// a vrati tento login-token
char *get_login_token()
{
    if (check_logged_in() == false)
        exit(1);

    char *login_token = NULL;
    size_t len = 0;
    FILE *fPtr;
    
    
    fPtr = fopen("login-token", "r");

    getline(&login_token, &len, fPtr);

    fclose(fPtr);


    return login_token;
}


// Funkcia ktora zisti kolko treba pridat spatnych lomitok
int how_many_backslash(char *body)
{
    int backslash = 0;
    int number_of_backslash = 0;
    int add = 0;

    for (int i = 0; i < strlen(body); i++)
    {
        if (body[i] == '\\')
        {
            number_of_backslash++;
            backslash = 1;
        }
        else if (backslash == 1)
        {
            backslash = 0;
        }
    }

    return number_of_backslash;
}

// Funkcia ktora vyrata aka bude dlha sprava klienta 
int length_of_msg(char *command, char *argv[], int argc, char *login_token)
{
    bool counting = false;              // urcuje ma pocitat znaky 
    int len = 0;                // celkova dlzka prikazu
    len = strlen(command);
    len += PARANTHESIS;         // (<message>)   
    int number_of_backslash = 0;// kolko tam je spatnych lomitok

    for (int i = 1; i < argc; i++)
    {
        // dlzka sa rata az od argumentu ktory obsahuje dajaky prikaz
        if (strcmp(command, argv[i]) == 0)
        {
            counting = true;
            continue;
        }    

        if (counting == true)    
        {
            if (strcmp(command, "fetch") == 0)
                len += strlen(argv[i]) + SPACE;                         // cislo nie je v uvodzovkach               
            else
            {
                len += how_many_backslash(argv[i]);
                len += strlen(argv[i]) + SPACE + QUOATATIONS_MARKS;   // napriklad: "<login>"
            }   
        }
    }

    if (login_token != NULL)
    {
        len += strlen(get_login_token()) + SPACE;
    }

    return len;
}


// Funkcia ktora vypisena na stdout status servera 
int print_server_status(char *server_msg)
{
    if (strstr(server_msg, "(ok "))     // (ok ...
    {
        printf("SUCCESS: ");
        return OK;
    }
    else                                // (err ...  
    {
        printf("ERROR: ");
        return ERROR;
    }    

}

// Funckia ktora vypise odpoved servera na zakladne dotazy
// ako REGISTER SEND LOGOUT alebou pri chybovej odpovedi servera
void print_server_basic_msg(char *server_msg)
{
    bool print_on = false;
    for (int i = 0; i < strlen(server_msg); i++)
    {   
        if (server_msg[i] == '"')
        {
            if (print_on)
                print_on = false;
            else
                print_on = true;

            continue;
        }

        if (print_on)
            printf("%c", server_msg[i]);
        
    }
    printf("\n");
}

// Funkcia ktora vypise odpoved servera na dotaz LOGIN
// a ulozi login-token do suboru
void print_server_login(char *server_msg)
{
    FILE *fPtr;                     
    bool print_on = false;              // urcuje ci sa maju vypisuvat znaky na stdout
    int quoatations_marks_cnt = 0;      // pocitadlo uvodzoviek

    remove("login-token");              // odstranenie login-tokenu (pri viac nasobnom prihlaseni) 
    fPtr = fopen("login-token", "a");

    for (int i = 0; i < strlen(server_msg); i++)
    {   
        if (server_msg[i] == '"')
        {
            quoatations_marks_cnt++;
            if (print_on)
                print_on = false;
            else
                print_on = true;

            if (quoatations_marks_cnt <= 2)                     // kontrola ci sa nahodou nejedna o login-token 
                continue;
            else                                                // ak je quoatations_marks_cnt > 2 jedna sa o login-token
            {
                fprintf(fPtr, "%c", server_msg[i]);             // zapisanie uvodzoviek do suboru login-token
                continue;
            }
        }

        if (print_on == true && quoatations_marks_cnt <= 2)
            printf("%c", server_msg[i]);
        else if (print_on && quoatations_marks_cnt > 2)         // jedna sa o login-token
            fprintf(fPtr, "%c", server_msg[i]);                 // zapisanie login-token do suboru
    
    }

    printf("\n");
    fclose(fPtr);
}

// Funkcia ktora vypise odpoved servena na dotaz LIST
void print_server_list(char *server_msg)
{
    bool printing_number;                               // urcuje ci sa maju znaky vypisovat na stdou
    int quoatations_marks_cnt = 0;                      // pocitadlo uvodzoviek

    printf("\n");
    
    for (int i = 4; i < strlen(server_msg); i++)        // zacina od 4 pretoze preskakuje status odpovede servera
    {
        if (server_msg[i] == '(')
        {
            printing_number = true;
            continue;
        }

        if (quoatations_marks_cnt == 2 || quoatations_marks_cnt == 4)
        {
            if (server_msg[i] != ' ')
                printf("\n");
        }

        if (server_msg[i] == ')')
        {
            quoatations_marks_cnt = 0;
            continue;
        }
        
        if (printing_number)
        {
            //if (server_msg[i] == '1' && server_msg[i+1] == ' ')
            //    printf("\n");
            
            printf("%c", server_msg[i]);

            if (server_msg[i+1] == ' ')
            {
                printf(":\n");
                printing_number = false;
            }
        }

        if (server_msg[i] == '"')
        {
            quoatations_marks_cnt++;
            if (quoatations_marks_cnt == 1)
                printf("  From: ");
            if (quoatations_marks_cnt == 3)
                printf("  Subject: ");

            continue;
        }

        if (quoatations_marks_cnt % 2 == 1)
            printf("%c", server_msg[i]);
    }
}

// Funkcia ktora vypise odpoved servena na dotaz FETCH
void print_server_fetch(char *server_msg)
{
    int quoatations_marks_cnt = 0;              // pocitadlo uvodzoviek
    int number_of_backslash = 0;

    char tmp_backslash[256];
    int cnt = 0;
    printf("\n\n");
    for (int i = 0; i < strlen(server_msg); i++)
    {
        if (server_msg[i] == '"')
        {
            quoatations_marks_cnt++;
            if (quoatations_marks_cnt == 1)
                printf("From: ");
            if (quoatations_marks_cnt == 3)
                printf("Subject: ");
            if (quoatations_marks_cnt == 2)
                printf("\n");
            if (quoatations_marks_cnt == 4)
                printf("\n\n");
            continue;
        }

        if (quoatations_marks_cnt % 2 == 1)
        {
            // kontrola ci sa tam nenechadya znak noveho riadku
            if (i + 1 < strlen(server_msg))
            {
                
                if ((server_msg[i] == '\\') && (server_msg[i+1] == 'n'))
                {
                    number_of_backslash = 0;
                    cnt = 0;
                    // zistenie kolko je spatnych lomitok
                    for (int j = i; j >= 0; j--)
                    {
                        if (server_msg[j] == '\\')
                        {
                            number_of_backslash++;
                            if (number_of_backslash % 2 != 0)
                            {
                                tmp_backslash[cnt] = '\\';
                                cnt++;
                                tmp_backslash[cnt] = '\0';
                            }
                        }
                        else
                            break;
                    }

                    // novy riadok sa urobi iba ak bolo jedno spatne lomitko
                    if (number_of_backslash == 1)
                        printf("\n");
                    else
                    {
                        printf("%s", tmp_backslash);
                        printf("n"); // IBA DEBUG !!!
                    }
                    
                    i++;
                    continue;
                }
            }
            if (server_msg[i] != '\\')
                printf("%c", server_msg[i]);
        }


    }
}

// Funkcia sluzi na vypis odpoved serveru na stdout
void print_server_msg(int command, char *server_msg)
{
    int server_status = print_server_status(server_msg);
    switch (command)
    {
        case REGISTER :
            print_server_basic_msg(server_msg);
            break;

        case LOGIN :
            if (server_status == ERROR)
                print_server_basic_msg(server_msg);
            else
                print_server_login(server_msg);
            break;

        case LIST :
            if (server_status == ERROR)
                print_server_basic_msg(server_msg);
            else            
                print_server_list(server_msg);
            break;

        case SEND :
            print_server_basic_msg(server_msg);
            break;

        case FETCH :
            if (server_status == ERROR)
                print_server_basic_msg(server_msg);
            else    
                print_server_fetch(server_msg);
            
            break;

        case LOGOUT :
            print_server_basic_msg(server_msg);
            remove("login-token");
            break;
    }
}

// Funckia ktora vracia n-tu mocninu dvojky 
int power_func(int powered)
{
    int result = 1;

    if (powered == 0)
        return 1;


    for (int i = 1; i <= powered; i++)
    {
        result *= 2; 
    }

    return result;
}

// Funkcia na prevod stringu do binarne podoby
char *to_bin(char *password)
{
    int shift;              
    int couter = 0;             
    int len = 0;                // dlzka bin cisla

    char letter;                // miesto na ukladanie pismena z hesla

    len = strlen(password) * 8; // binarna hodnota pismena reprezentovana na 8bitoch 
    
    if (len % 6 != 0)
        len += 6 - (len % 6);

    
    char *bin_number = malloc(len + 1);     // heslo v binarnej podobe na 8bitoch
    
    // prevod hesla do binarnej podoby na 8bitoch
    for (int i = 0; i < strlen(password); i++)
    {
        letter = password[i];
        for (int j = 7; j >= 0; j--)
        {
            shift = letter >> j;

            if (shift & 1)
                bin_number[couter] = '1';
            else
                bin_number[couter] = '0';
            
            couter++;
        }
    }

    bin_number[couter] = '\0';              // ukoncenie retazca

    return bin_number;
}


// Funckia na zasifrovanie hesla pomocou base64
char *base64_encoding(char *password)
{
    int len;                    // dlzka bin cisla
    int result = 0;             // decimalna hodnota 6bitov z hesla
    int cnt = 5;
    int letter_couter = 0;      // pocet pismen sirfy

    char *bin_number = to_bin(password);        // binarna reprezentacia hesla
    len = strlen(bin_number);

    char *encoded_password = malloc(len + 1);   // zasifrovane heslo

    // sifrovanie 
    for (int i = 0; i < len; i++)
    {
        if (bin_number[i] == '1')
            result += power_func(cnt);

        cnt--;

        // kontrola ci nacitalo 6 bitov alebo je koniec binarneho cisla
        if (cnt == -1 || (i == len - 1))
        {
            encoded_password[letter_couter] = base64_table[result];         // priradenie danej sifry na zaklade decimalnej hodnoty
            cnt = 5;
            result = 0;
            letter_couter++;
        }    
    }
    
    encoded_password[letter_couter] = '\0';         // ukoncenie retazca


    // osetrenie ak sirfa nie je delitelna 4 tak sa doplni znak =
    if (strlen(encoded_password) % 4 != 0)
    {
        int missing_chars = 4 - strlen(encoded_password) % 4;
        for (int k = 0; k < missing_chars; k++)
        {
            encoded_password[letter_couter] = '=';
            letter_couter++;
        }
        encoded_password[letter_couter] = '\0';     // ukoncenie retazca
    }

    free(bin_number);

    return encoded_password;
}


// Funkcia ktora osetri escape sekvencie
char *manage_backslash(char *body)
{
    int backslash = 0;              // reprezentuje ci bolo '\' nacitane
    int number_of_backslash = 0;
    int add = 0;                    // kolko ma pridat spatnych lomitok

    add = how_many_backslash(body);

    char *tmp = malloc(strlen(body) + add + 1);
    
    // prechadzanie pravy pokial tam je "\" nahradi ho dvoma "\\"
    for (int i = 0; i < strlen(body); i++)
    {
        if (body[i] == '\\')
        {
            backslash = 1;
            number_of_backslash++;
        }
        else 
        {
            if (backslash == 1)
            {
                for (int j = 0; j < number_of_backslash; j++)
                {
                    strcat(tmp, "\\");
                    strcat(tmp, "\\");
                }
                
                number_of_backslash = 0;
                backslash = 0;
            }
            strncat(tmp, &body[i], 1);
        }
    }

    return tmp;
}

// Tato cast kodu bola prevzata a upravene 
    // zdroj : https://gist.github.com/jirihnidek/bf7a2363e480491da72301b228b35d5d
char *get_ip_address(char *host_name)
{
    struct addrinfo hints;
    struct addrinfo *result;
    struct addrinfo *ptr;

    char ip_addr[256];
    int err = 0;
    int tmp_socket;

    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;
    
    memset(&hints, 0, sizeof(hints));

    err = getaddrinfo(host_name, NULL, &hints, &result);

    if (err != 0)
    {
        printf("Error in getaddrinfo \n");
        exit(1);
    }

    // prechadzanie cez vsetky adresy
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next)
    {
        tmp_socket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);

        // kontrola ci sa da pripojit na socket
        if (tmp_socket == -1)
        {
            close(tmp_socket);
            continue;
        }
        
        // skusi sa pripojit na danu ip adresu
        if (bind(tmp_socket, ptr->ai_addr, ptr->ai_addrlen) != -1)
        {
            getnameinfo(ptr->ai_addr, ptr->ai_addrlen, ip_addr, sizeof(ip_addr ), NULL, 0, NI_NUMERICHOST);
            close(tmp_socket);
            break;
        }
    }

    char *tmp_ip_addr = malloc(strlen(ip_addr) + 1);
    tmp_ip_addr = ip_addr;

    freeaddrinfo(result);
    
    return tmp_ip_addr;
}



int main (int argc, char *argv[]){

    int client_socket;
    int conect_status;
    struct sockaddr_in6 server_addr6;
    struct sockaddr_in server_addr4;

    char *all_msg_server = NULL;            // buffer na celu spravu serveru
    all_msg_server = malloc(1025);
    memset(all_msg_server, 0, 1025);
    
    char part_of_msg[1024];                 // bufer na cast spravy od serveru ktora ma velksot 1024 bitov
    memset(part_of_msg, 0, 1024);

    int cnt_of_packet = 0;

    int addr_ipv4;                          // premena urcuje ci sa jedna o ipv4
    int addr_ipv6;                          // premena urcuje ci sa jedna o ipv6

    char ip_addr_server [256];
    int port_number;                // defaul 32323
    bool port_bool = false;
    bool addr_bool = false;
    char *username = NULL;
    char *password = NULL;

    char *recipient = NULL;
    char *subject = NULL;
    char *body = NULL;
    char *fetch_id = NULL;

    int command = -1;    // command for server 
    
    char *command_name = NULL;

    int len;
    char *logn = NULL;
    int len_base64 = 0;
    char *encoded_password = NULL;

    
    // parsovanie argumentov
    for (int i = 1; i < argc; i++)
    {
        // switch -h || --help
        if ((strcmp(argv[i], "-h") == 0) || (strcmp(argv[i], "--help") == 0))
        {
            print_help();
            return(0);
        }

        // switch -a || --address
        if ((strcmp(argv[i], "-a") == 0) || (strcmp(argv[i], "--address") == 0))
        {
            addr_bool = true;
            if (i + 1 < argc)               // kontrola ci bola zadana adresa
                strcpy(ip_addr_server, argv[i+1]);
            else
            {
                printf("client: the \"-a\" option needs 1 argument, but 0 provided\n");
                return 1;
            }
        }

        // switch -p || --port
        if ((strcmp(argv[i], "-p") == 0) || (strcmp(argv[i], "--port") == 0))
        {
            port_bool = true;
            if (i + 1 < argc)               // kontrola ci bol zadani port
            {
                port_number = atoi(argv[i+1]);
                if (port_number == 0)
                {
                    printf("Port number is not a string\n");
                    return 1;
                }
            }
            else
            {
                printf("client: the \"-p\" option needs 1 argument, but 0 provided\n");
                return 1;
            }
        }

        //Podporovane prikazy
        //register
        if (strcmp(argv[i], "register") == 0)
        {
            if ((i + 2 < argc) && (argc <= 8))
            {
                command_name = argv[i];
                username = argv[i+1];
                password = argv[i+2];
                command = REGISTER;
            }
            else {
                printf("register <username> <password>\n");
                return 1;
            }
        }

        //login
        if (strcmp(argv[i], "login") == 0)
        {
            if ((i + 2 < argc) && (argc <= 8))
            {
                command_name = argv[i];
                username = argv[i+1];
                password = argv[i+2];
                
                command = LOGIN;
            }
            else {
                printf("login <username> <password>\n");
                return 1;
            }
        }

        //list
        if (strcmp(argv[i], "list") == 0)
        {
            command_name = argv[i];
            command = LIST;
        }

        //send
        if (strcmp(argv[i], "send") == 0)
        {
            if ((i + 3) < argc)
            {
                command_name = argv[i];
                recipient = argv[i+1];
                subject = argv[i+2];

                //body = argv[i+3];
                body = manage_backslash(argv[i+3]);
                command = SEND;
            }
            else {
                printf("send <recipient> <subject> <body>\n");
                return 1;
            }
        }

        //fetch
        if (strcmp(argv[i], "fetch") == 0)
        {
            if (i + 1 < argc)
            {
                command_name = argv[i];
                command = FETCH;
                fetch_id = argv[i+1];
            }
            else
            {
                printf("fetch <id>\n");
                return 1;
            }
        }

        //logout
        if (strcmp(argv[i], "logout") == 0)
        {
            command = LOGOUT;
            command_name = argv[i];
        }
    }

    if (command == -1)
    {
        printf("unknown command\n");
        return 1;
    }

    if (command == LOGIN || command == REGISTER) 
    {
        encoded_password = base64_encoding(password);
        len_base64 = strlen(encoded_password);
        len = len_base64 - strlen(password);
        len += length_of_msg(command_name, argv, argc, NULL);
    }
    else {
        logn = get_login_token();
        len = length_of_msg(command_name, argv, argc, logn);
    }

    char client_msg[len];
    
    // Vytvorenie spravy klienta
    switch (command)
    {
        case REGISTER :
            strcpy(encoded_password, base64_encoding(password));

            snprintf(client_msg, len, "(register \"%s\" \"%s\"", username, encoded_password);
            strcat(client_msg, ")");

            free(encoded_password);
            break;
        
        case LOGIN :
            strcpy(encoded_password, base64_encoding(password));

            snprintf(client_msg, len, "(login \"%s\" \"%s\"", username, encoded_password);
            strcat(client_msg, ")");

            free(encoded_password);
            break;
        

        case LIST :
            snprintf(client_msg, len, "(list %s)", logn);
            strcat(client_msg, ")");
            break;

        case SEND :
            snprintf(client_msg, len, "(send %s \"%s\" \"%s\" \"%s\"", logn, recipient, subject, body);
            strcat(client_msg, ")");

            free(body);
            break;

        case FETCH :
            snprintf(client_msg, len, "(fetch %s %s", logn, fetch_id);
            strcat(client_msg, ")");
            break;

        case LOGOUT :
            snprintf(client_msg, len, "(logout %s", logn);
            strcat(client_msg, ")");
            break;
    }

    // Kontrola ci bola zadana adresa
    if (addr_bool == false)                         // ak nie je zadana adresa defaul localhost
        strcpy(ip_addr_server, "::1");          

    //Kontrola ci bol zadany port
    if (port_bool == false)                     
        port_number = 32323;                        // ak nie je zadany port defaul 32323


    addr_ipv4 = inet_pton(AF_INET, ip_addr_server, &server_addr6.sin6_addr);
    addr_ipv6 = inet_pton(AF_INET6, ip_addr_server, &server_addr6.sin6_addr);

    // ak bola zadana domena
    if (addr_ipv4 == 0 && addr_ipv6 == 0)
    {
        char *tmp_ip_addr_server = get_ip_address(ip_addr_server); 

        addr_ipv4 = inet_pton(AF_INET, tmp_ip_addr_server, &server_addr6.sin6_addr);
        addr_ipv6 = inet_pton(AF_INET6, tmp_ip_addr_server, &server_addr6.sin6_addr);
    }

    if (addr_ipv6 == 1)                           //Ipv6
    {
        client_socket = socket(AF_INET6, SOCK_STREAM, 0);

        server_addr6.sin6_family = AF_INET6;
        server_addr6.sin6_port = htons(port_number);     

        conect_status = connect(client_socket, (struct sockaddr *) &server_addr6, sizeof(server_addr6));
    }
    else if (addr_ipv4 == 1)                      //IPv4
    {
        client_socket = socket(AF_INET, SOCK_STREAM, 0);

        server_addr4.sin_family = AF_INET;    
        server_addr4.sin_port = htons(port_number);      
        inet_pton(AF_INET, ip_addr_server, &server_addr4.sin_addr);

        conect_status = connect(client_socket, (struct sockaddr *) &server_addr4, sizeof(server_addr4));
    }


    if (conect_status == -1) {
        printf("Error unable connect to server \n");
        return 1;
    }

    
    if (send(client_socket, client_msg, len, 0) < 0)
    {
        printf("Unable to send message\n");
        return 1;
    }

    while (recv(client_socket, part_of_msg, sizeof(part_of_msg) - 1, 0) > 0)
    {
        cnt_of_packet++;
        all_msg_server = realloc(all_msg_server, cnt_of_packet*1025);

        strcat(all_msg_server, part_of_msg);

        memset(part_of_msg, 0, 1024);

    }
    
    print_server_msg(command, all_msg_server);    

    free(all_msg_server);

    close(client_socket);

    return 0;
}