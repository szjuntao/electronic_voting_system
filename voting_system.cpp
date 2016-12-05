#include <cstdio>       /* standard C i/o facilities */
#include <cstdlib>      /* needed for atoi() */
#include <cstring>      /* c-string Library */
#include <string>       /* c++ string */
#include <map>
#include <vector>
#include <unistd.h>
#include <iostream>
#include <ctime>

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#include "paillier.h"


bool read_voter_list(char* filename);
bool read_candidate_list(char* filename);
bool read_rsa_key(char* pri_file, char* pub_file);
bool generate_paillier_keys();

bool login();
void post_login_action();
void cast_a_vote();
void view_vote();

unsigned char* blind_signature(const std::vector<BIGNUM*>& vote, unsigned int &len);
bool verify_signature(const std::vector<BIGNUM*>& vote, unsigned char* sig, unsigned int sig_len);

void transfer_votes_to_ca();
bool calc_vote( std::vector<BIGNUM*> &result );

void BN_printf(BIGNUM *num);
bool paillier_encryption( std::vector<BIGNUM*> &vote, std::vector<BIGNUM*> &rands);
bool paillier_decryption( std::vector<BIGNUM*> &result );
void announce_winner(const std::vector<BIGNUM*> &result);
bool zero_knowledge_proof(BIGNUM* ori_msg, BIGNUM* ori_c, BIGNUM* ori_ra);

void print_signature(unsigned char *str, unsigned int len);

std::map<std::string, std::string> voters;
std::vector<std::string> candidates;
std::string current_voter;

std::map< std::string, std::vector<BIGNUM*> > bulletin_board;
std::vector< std::vector<BIGNUM*> > counting_authority;

RSA* rsa_public_key;
RSA* rsa_private_key;
BN_CTX *ctx;
paillierKeys paillier_keys;    // struct containing both private/public key

typedef std::map<std::string, std::string>::iterator vitr;
typedef std::map<std::string, std::string>::const_iterator cvitr;

/*
  openssl genrsa -out private.pem 2048
  openssl rsa -in private.pem -outform PEM -pubout -out public.pem
*/

int main(int argc , char *argv[]) {

  if ( argc != 5 ) {

    fprintf(stderr, "Incorrect arguments.\n");
    printf("Usage: ./a.out <voter_list> <candidates_list> <private RSA key> <public RSA key>\n");
    exit(-1);
  }

  if (!read_voter_list(argv[1])) {
    fprintf(stderr, "Error reading voter information.\n");
    exit(-1);
  }

  if (!read_candidate_list(argv[2])) {
    fprintf(stderr, "Error reading candidates information.\n");
    exit(-1);
  }

  // generate RSA public and private key
  if (!read_rsa_key(argv[3], argv[4])) {
    fprintf(stderr, "Error reading rsa public/private key.\n");
    exit(-1);
  }

  // generate Paillier public and private key
  ctx = BN_CTX_new();
  if (!generate_paillier_keys()) {
    fprintf(stderr, "Error generating paillier keys.\n");
    exit(-1);
  }

  #if DEBUG
  for (cvitr citr = voters.begin(); citr != voters.end(); citr++) {
    printf("<%s, %s>\n", citr->first.c_str(), citr->second.c_str());
  }
  printf("number of voters: %lu\n", voters.size());

  printf("Candidates: \n");
  for(int i = 0; i < candidates.size(); i++)
    printf("  %s\n", candidates[i].c_str());
  #endif

  std::string in;
  while(1) {

    if (bulletin_board.size() == voters.size()) {

      printf("All voters has voted. Sending votes to Counting Authority...\n");

      transfer_votes_to_ca();
      std::vector<BIGNUM*> result;
      if (!calc_vote(result)) {
        fprintf(stderr, "Error - calc_vote()\n");
        exit(-1);
      }

      printf("\nReceived result from Counting Authority.\n");
      printf("Decrypting Result...\n");

      if (!paillier_decryption(result)) {
        fprintf(stderr, "Error - paillier_decryption()\n");
        exit(-1);
      }

      printf("\n\n------ result -------\n");
      for (int j = 0; j < result.size(); j++) {
        printf("%s ", candidates[j].c_str());
        BN_printf(result[j]);
      }
      printf("\n");

      announce_winner(result);
      exit(0);
    }

    printf("\nAction: (input number)\n");
    printf("1. Voter Login\n");
    printf("2. Exit\n");

    std::cin >> in;
    if (in == "1") {

      if (login()) {

        printf("\n*** Login Success! Voter: %s\n", current_voter.c_str());
        post_login_action();

      } else {

        printf("\n*** Authentication Failed.\n");

      } 

    } else if (in == "2") break;

    else {
      printf("Invalid Input\n");
      continue;
    }
  }

  return 0;
}

bool read_voter_list(char* filename) {

  char buff[128];
  char *p;
  std::string name, pw;

  FILE *in = fopen(filename, "r");
  if (!in) return false;

  while ( fgets(buff, 128, in) ) {

    p = strtok(buff, " ");
    if (!p) return false;
    name = p;

    p = strtok (NULL, " ");
    if (!p) return false;
    p [strlen(p)-1] = '\0';
    pw = p;

    voters.insert( std::pair<std::string, std::string> (name, pw));
  }

  return true;
}

bool read_candidate_list(char* filename) {

  char buff[128];

  std::string name;

  FILE *in = fopen(filename, "r");
  if (!in) return false;

  while ( fgets(buff, 128, in) ) {

    if (buff[strlen(buff)-1] == '\n') buff[strlen(buff)-1] = '\0';
    name = buff; 
    candidates.push_back(name);
  }

  return true;
}

bool read_rsa_key(char* pri_file, char* pub_file) {

  // open pem file
  FILE* pubkey_fp = fopen(pub_file, "r");
  FILE* prikey_fp = fopen(pri_file, "r");
  if (!pubkey_fp || !prikey_fp) {
    return false;
  }

  rsa_public_key = PEM_read_RSA_PUBKEY(pubkey_fp, NULL, NULL, NULL);
  rsa_private_key = PEM_read_RSAPrivateKey(prikey_fp, NULL, NULL, NULL);

  if (rsa_public_key == NULL || rsa_private_key == NULL) return false;
  else return true;
}

bool generate_paillier_keys() {

  int len = 32;
  if (generateRandomKeys(&paillier_keys, &len, ctx) != 0) return false;

  return true;
}

bool login() {

  std::string username, password;

  printf("Enter User Name: ");
  std::cin >> username;

  password = getpass("Enter Password: ");

  cvitr citr = voters.find(username);
  if (citr == voters.end()) return false;
  else if (citr->second != password) return false;
  else current_voter = citr->first;

  return true;
}

void post_login_action() {

  std::string in;
  while(1) {

    printf("\nAction: (input number)\n");
    printf("1. Cast a vote\n");
    printf("2. Logout\n");

    std::cin >> in;
    if (in == "1") {

      if (bulletin_board.find(current_voter) != bulletin_board.end()) {
        printf("You have voted. Cannot cast a vote again.\n");
        continue;
      }
      cast_a_vote();

    } else if (in == "2") {

      current_voter = "";
      break;
    } 

    else continue;
  }
}

void cast_a_vote() {

  std::string in;
  int i, c;

  printf("\nSelect a candidate from the list: (input number)\n");
  for(int j = 0; j < candidates.size(); j++)
    printf("  %d. %s\n", j+1, candidates[j].c_str());

  // validate input
  while(1) {

    std::cin >> in;
    if (in.length() > 5) goto input_again; // input number too large

    for(i = 0; i < in.length(); i++)
      if (in[i] < '0' || in[i] > '9') break;

    if (i != in.length()) goto input_again; // input is not a number

    c = atoi(in.c_str());
    if (c < 1 || c > candidates.size()) goto input_again;
    c--; // count from 1 => count from 0

    break;

    input_again:
    printf("Invalid input. Please try again.\n");
  }

  printf("\nSelect Candidate: %s\n\n", candidates[c].c_str());
  
  // construct a vote
  std::vector<BIGNUM*> a_vote, plain_vote;
  BIGNUM *v, *u;
  for(int j = 0; j < candidates.size(); j++) {

    v = BN_CTX_get(ctx);
    u = BN_CTX_get(ctx);
    if (j != c) {

      if (!BN_zero(v) || !BN_zero(u)) {
        fprintf(stderr, "Error when creating vote.\n");
        exit(-1);
      }

    } else {

      if (!BN_one(v) || !BN_one(u)) {
        fprintf(stderr, "Error when creating vote.\n");
        exit(-1);
      }
    }
    a_vote.push_back(v);
    plain_vote.push_back(u);
  }

  // encrypting vote with paillier
  printf("Encrypting this vote with Paillier Encryption...\n\n");
  std::vector<BIGNUM*> rand_num_record;
  if (!paillier_encryption( a_vote, rand_num_record)) {
    fprintf(stderr, "Error - encrypt vote with paillier\n");
    exit(-1);
  }

  printf("Cipher text for this vote: \n");
  for (int j = 0; j < a_vote.size(); j++)
    BN_printf(a_vote[j]);
  printf("\n");

  // sign this vote
  printf("\nBlind Signing the encrypted vote...\n");
  unsigned int len;
  unsigned char *sig = blind_signature(a_vote, len);

  // verify signature
  printf("\nVerifying Signature...\n");
  if(!verify_signature(a_vote, sig, len)) {
    printf("Invalid Signature. Aborting this vote...\n");
    return;
  }
  free(sig);

  // performs a zero knowledge proof
  printf("\nPerforming zero-knowledge-proof...\n");
  for (int j = 0; j < a_vote.size(); j++) {

    if(!zero_knowledge_proof(plain_vote[i], a_vote[i], rand_num_record[j])) {
      
      fprintf(stderr, "Failed - Zero Knowledge Proof.\n");
      exit(-1);
    }
  }
  printf("Zero Knowledge Proof passed\n");
  
  printf("Sending this vote to bulletin board...\n");

  bulletin_board.insert( std::pair<std::string, std::vector<BIGNUM*> > (current_voter, a_vote));
}

void print_signature(unsigned char *str, unsigned int len) {

  printf("Signature: ");
  int i;
  char a, b;
  for(i = 0; i < len; i++) {
    a = str[i]>>4;
    b = str[i] & 0x0f;
    if (a < 10) a += 48; // 0x0 ~ 0x9
    else a += 87;        // 0xa ~ 0xf
    if (b < 10) b += 48;
    else b += 87;
    printf("%c%c", a, b);
  }
  printf("\n\n");
}

void view_vote() {
}

void transfer_votes_to_ca() {

  std::map< std::string, std::vector<BIGNUM*> >::const_iterator citr;
  for(citr = bulletin_board.begin(); citr != bulletin_board.end(); citr++) {
    counting_authority.push_back( citr->second );
  }
}

bool calc_vote( std::vector<BIGNUM*> &result) {

  BIGNUM *vote_sum;
  for(int i = 0; i < candidates.size(); i++) {

    vote_sum = BN_CTX_get(ctx);
    if(!BN_copy(vote_sum, counting_authority[0][i])) return false;

    for(int j = 1; j < voters.size(); j++) {

      if(!BN_mod_mul(vote_sum, vote_sum, counting_authority[j][i], paillier_keys.pub.n2, ctx)) return false;
      
    }
    result.push_back(vote_sum);
  }
  return true;
}

bool paillier_encryption( std::vector<BIGNUM*> &vote, std::vector<BIGNUM*> &rands ) {

  BIGNUM *inter1 = BN_CTX_get(ctx);
  BIGNUM *inter2 = BN_CTX_get(ctx);
  BIGNUM *result;
  BIGNUM *ra;

  for (unsigned int i = 0; i < vote.size(); i++) {

    result = BN_CTX_get(ctx);
    ra  = BN_CTX_get(ctx);

    // performs a paillier encryption
    if (!BN_rand(ra, 8, 0, 0)) return false;
    while (BN_is_negative(ra))
      if (!BN_rand(ra, 8, 0, 0)) return false;

    if (!BN_mod_exp(inter1, paillier_keys.pub.g, vote[i], paillier_keys.pub.n2, ctx)) return false;
    if (!BN_mod_exp(inter2, ra, paillier_keys.pub.n, paillier_keys.pub.n2, ctx)) return false;
    if (!BN_mod_mul(result, inter1, inter2, paillier_keys.pub.n2, ctx)) return false;
    //printf("result: "); BN_printf(result);
    vote[i] = result;
    //printf("vote[i]: "); BN_printf(vote[i]);
    rands.push_back(ra);
  }

  return true;
}

bool paillier_decryption( std::vector<BIGNUM*> &result ) {

  BIGNUM* decrypt_result;
  for (unsigned int i = 0; i < result.size(); i++) {

    decrypt_result = BN_CTX_get(ctx);
    if( decrypt(decrypt_result, result[i], &paillier_keys.priv, ctx) != 0) return false;
    result[i] = decrypt_result;
  }

  return true;
}

void announce_winner(const std::vector<BIGNUM*> &result) {

  unsigned long tmp;
  std::vector<unsigned long> ul_result;
  for(int i = 0; i < result.size(); i++) {
    tmp = BN_get_word(result[i]);
    ul_result.push_back(tmp);
  }

  // find the largest
  tmp = 0;
  for(int i = 1; i < ul_result.size(); i++) {
    if (ul_result[tmp] < ul_result[i]) tmp = i;
  }

  printf("\n\nWinner: %s\n\n", candidates[tmp].c_str());
}

bool zero_knowledge_proof(BIGNUM* ori_msg, BIGNUM* ori_c, BIGNUM* ori_ra) {

  BIGNUM *ra = BN_CTX_get(ctx);
  BIGNUM *msg = BN_CTX_get(ctx);

  if (!BN_rand(ra, 8, 0, 0)) return false;

  //if(!BN_rand(msg, 3, 0, 0)) return false;
  if(!BN_set_word(msg, 0));

  printf("Generated random number(8bits) and random msg(3bits).\n");

  BIGNUM *inter1 = BN_CTX_get(ctx);
  BIGNUM *inter2 = BN_CTX_get(ctx);
  BIGNUM *result = BN_CTX_get(ctx);

  // performs a paillier encryption
  if(!BN_mod_exp(inter1, paillier_keys.pub.g, msg, paillier_keys.pub.n2, ctx)) return false;
  if(!BN_mod_exp(inter2, ra, paillier_keys.pub.n, paillier_keys.pub.n2, ctx)) return false;
  if (!BN_mod_mul(result, inter1, inter2, paillier_keys.pub.n2, ctx)) return false;

  printf("result: "); BN_printf(result);
  printf("Sent encrypted msg to board.\n");

  // e must be positive
  BIGNUM *e = BN_CTX_get(ctx);
  if (!BN_rand(e, 8, 0, 0)) return false;
  while (BN_is_negative(e))
    if (!BN_rand(e, 8, 0, 0)) return false;

  printf("Return value e (8bits): "); BN_printf(e);

  printf("computing v & w...\n");

  BIGNUM *v = BN_CTX_get(ctx);
  if(!BN_mul(inter1, e, ori_msg, ctx)) return false;  // em
  if(!BN_sub(v, msg, inter1)) return false;           // v=r-em

  BIGNUM *w = BN_CTX_get(ctx);

  BIGNUM* nihil = BN_CTX_get(ctx);
  if(!BN_zero(nihil)) return false;
  if(!BN_sub(inter1, nihil, e)) return false;              // inter1 = -e

  if(!BN_exp(inter2, ori_ra, inter1, ctx)) return false;   // inter2 = x^-e
  if(!BN_mul(w, ra, inter2, ctx)) return false;            // w = s(x^-e)

  printf("Sending v & w...\n");
  
  if(!BN_mod_exp(inter1, paillier_keys.pub.g, v, paillier_keys.n2, ctx)) return false;  //inter1 = g^v % N^2
  if(!BN_mod_exp(inter2, ori_c, e, paillier_keys.n2, ctx)) return false;                //inter2 = c^e % N^2
  if(!BN_mod_mul(inter2, inter1, inter2, paillier_keys.n2, ctx)) return false;          //inter2 = g^v.c^e % N^2
  if(!BN_mod_exp(inter1, w, paillier_keys.n, paillier_keys.n2, ctx)) return false;      //inter1 = w^N % N^2
  if(!BN_mod_mul(inter2, inter1, inter2, paillier_keys.n2, ctx)) return false;          //inter2 = g^v.c^e.w^n %N^2

  return BN_cmp(inter2,result)%2;
}

unsigned char* blind_signature(const std::vector<BIGNUM*>& vote, unsigned int &len) {


  std::string ss;
  for(int i = 0; i < vote.size(); i++) {
    char *ptr = BN_bn2hex(vote[i]);
    ss += ptr;
    OPENSSL_free(ptr);
  }

  unsigned char* condense = (unsigned char*)malloc(64*sizeof(unsigned char));

  SHA512_CTX c;
  SHA512_Init(&c);
  SHA512_Update(&c, (unsigned char*)ss.c_str(), ss.length());
  SHA512_Final(condense, &c);
  
  printf("Blind vote generated, length 64 bytes\n");
  printf("Performing RSA encryption on blinded vote...\n");
  
  unsigned char *encrypt = (unsigned char*)malloc(RSA_size(rsa_public_key));
  len = RSA_public_encrypt(64, condense, encrypt, rsa_public_key, RSA_PKCS1_PADDING);
  printf("RSA_public_encrypt(): success.\n");

  free(condense);
  return encrypt;
}

bool verify_signature(const std::vector<BIGNUM*>& vote, unsigned char* sig, unsigned int sig_len) {

  unsigned char* decrypt = (unsigned char*)malloc(RSA_size(rsa_private_key));
  int len = RSA_private_decrypt(sig_len, sig, decrypt, rsa_private_key, RSA_PKCS1_PADDING);

  printf("len: %d\n", len);

  std::string ss;
  for(int i = 0; i < vote.size(); i++) {
    char *ptr = BN_bn2hex(vote[i]);
    ss += ptr;
    OPENSSL_free(ptr);
  }

  unsigned char* condense = (unsigned char*)malloc(64*sizeof(unsigned char));

  SHA512_CTX c;
  SHA512_Init(&c);
  SHA512_Update(&c, (unsigned char*)ss.c_str(), ss.length());
  SHA512_Final(condense, &c);

  int diff = memcmp(condense, decrypt, 64);
  if(diff == 0) {

    printf("Signature verified. This vote is valid.\n");
    return true;

  } else {

    printf("Signature is not valid. This vote is fake.\n");
    return false;
  }
}

//This function is copied from the paillier encryption code
//This function is just for testing
void BN_printf(BIGNUM *num) 
{
        BIO *out = NULL;

        out = BIO_new(BIO_s_file());

        if (out == NULL)
                exit(1);

        BIO_set_fp(out, stdout, BIO_NOCLOSE);

        BN_print(out, num);
        printf("\n");

        BIO_free(out);
        CRYPTO_mem_leaks(out);
}

