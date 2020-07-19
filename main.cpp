#include "./include/socketcan_cpp.h"
#include <string.h>
#include <iostream>
#include<sstream>
#include "./include/crypto.h"
#include <stdio.h>
#include <unistd.h>
#include <cmath>

#define FRAME_DIM  64
#define RSA_KEY_LENGTH 256
#define SIGN_LENGTH 344
#define MAX_MSG_LENGTH 253
#define MAX_N_FRAME (SIGN_LENGTH+RSA_KEY_LENGTH)/FRAME_DIM
#define CASUAL_ID 125

using namespace std;

int main(){

    scpp::SocketCan sockat_can;
    scpp::CanFrame fr;

    char action;
    printf("Type W for writing or R for reading = ");
    scanf("%c", &action);

    //Opening socket
    if (sockat_can.open("vcan0") == scpp::STATUS_OK){

        //READING FUNCTION
        if (action == 'r' || action == 'R') {

            //Copying public key from pem file
            ifstream f2("../public.pem"); //taking file as inputstream
            string pub;
            if(f2) {
                ostringstream ss;
                ss << f2.rdbuf(); // reading data
                pub = ss.str();
            }

            //Initializing parameters
            int i;
            char temp[MAX_N_FRAME * FRAME_DIM];
            char signature[SIGN_LENGTH];
            char msg[RSA_KEY_LENGTH];

            //Reading. Without knowing how many frames we'll receive, we have to rely on an in-message control
            bool break_out = false;
            for (i = 0; i < MAX_N_FRAME; i++) {
                if(break_out)
                    break;
                if(sockat_can.read(fr) == scpp::STATUS_OK){
                    for(int n = 0; n < FRAME_DIM; n++) {
                        temp[n + (i * FRAME_DIM)] = fr.data[n];

                        //Stop reading frames when three chars are 0 --> control
                        if (temp[n + (i * FRAME_DIM)] == '0' && temp[n + (i * FRAME_DIM) - 1] == '0' && temp[n + (i * FRAME_DIM) - 2] == '0')
                            break_out = true;
                    }
                }
                else
                    return scpp::STATUS_READ_ERROR;
                printf("Read\n");
            }

            printf("\n");

            //Copying signature from temporary array
            strncpy(signature, temp, SIGN_LENGTH);

            //Copying the message from temp. array, stopping when three chars are 0 -stop signal-
            int s;
            for(s = 0, i = SIGN_LENGTH; i<MAX_N_FRAME*FRAME_DIM; i++, s++) {
                if (temp[i] == '0' && temp[i + 1] == '0' && temp[i + 2] == '0') {
                    break;
                } else
                    msg[s] = temp[i];
            }

            //Creating correct-dimension strings from arrays
            std::string strmsg(msg, s);
            std::string strsig(signature, SIGN_LENGTH);

            //Displaying what's recieved
            printf("\n");
            printf("%s\n", "Check signature: ");
            for(int i=0; i<SIGN_LENGTH; i++)
                printf("%c", signature[i]);
            printf("\n");
            printf("%s\n", "Check message: ");
            for(int i=0; i<strmsg.length(); i++)
                printf("%c", strmsg[i]);
            printf("\n");

            printf("Finished copying message and signature\n");


            //Verify signature with public key
            bool authentic = cry::verifySignature(pub, strmsg, strsig);


            if (authentic)
                printf("Message is authentic");
            else
                printf("Message is not authentic");

        }

        //WRITING FUNCTION
        else if (action == 'w' || action == 'W') {

            //Copying private key from pem file
            ifstream f1("../private.pem"); //taking file as inputstream
            string priv;

            if(f1) {
                ostringstream ss;
                ss << f1.rdbuf(); // reading data
                priv = ss.str();
            }

            //Defining message
            std::string msgstr = "Hello World";

            //Check on length --> Max 253 chars because three are for control
            if(msgstr.length() > MAX_MSG_LENGTH){
                printf("Error message length, max 253 characters");
                return -1;
            }

            //Determine how many frames we'll transmit
            int tot_trans_dim = (SIGN_LENGTH + (int)msgstr.length());
            int n_frame = ceil(tot_trans_dim/FRAME_DIM) + 1;
            char tot_msg[tot_trans_dim];

            //Signing message with private key
            std::string privstr(priv);
            std::string sigstr = cry::signMessage(privstr, msgstr);

            //Creating an array composed with both signature and message
            int i, j = 0;
            for (i = 0; i < SIGN_LENGTH; i++)
                tot_msg[i] = sigstr[i];

            if(msgstr.length() < MAX_MSG_LENGTH){
                for (j = 0, i = SIGN_LENGTH; i < SIGN_LENGTH + msgstr.length(); i++, j++)
                    tot_msg[i] = msgstr[j];
                for(i = SIGN_LENGTH + msgstr.length(); i < SIGN_LENGTH + msgstr.length() + 3; i++)
                    tot_msg[i] = '0';
            }

            //Writing. n_frame depends on message length
            fr.id = CASUAL_ID;
            fr.len = FRAME_DIM;
            for (int i = 0; i < n_frame; i++) {
                for (int k = 0; k < FRAME_DIM; k++){
                    fr.data[k] = tot_msg[k + i*FRAME_DIM];
                }

                int write_status = sockat_can.write(fr);
                if(write_status == scpp::STATUS_OK)
                    printf("Written\n");
            }


            //Displaying what's transmitted
            printf("\n");
            printf("%s\n", "Signature to transmit: ");

            for(int i=0; i<SIGN_LENGTH; i++)
                printf("%c", sigstr[i]);

            printf("\n");
            printf("%s\n", "Message to transmit: ");

            for(int i=0; i<msgstr.length(); i++)
                printf("%c", msgstr[i]);
            printf("\n");

        }
        else {
            printf("Error choosing action");
        }
    }
    else{
        printf("Cannot open can socket!");
    }
    
    return 0;
}