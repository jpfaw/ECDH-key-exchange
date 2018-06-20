// gcc -o proxy proxy.c -ltepla -lssl -lgmp -lcrypto -std=c99

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gmp.h>
#include <sys/time.h>
#include <tepla/ec.h>
#include <openssl/sha.h>

typedef enum{
    ADD,
    SUB,
    XOR
}Mode;

// プロトタイプ宣言
void print_green_color(const char *text);
void create_mpz_t_random(mpz_t op, const mpz_t n);
void print_unsigned_char(const unsigned char *uc, const char *dataName, const size_t size);
void calculation(Mode mode, unsigned char *ciphertext, const unsigned char *hash,
                 const char *text, const size_t hashSize, const size_t textSize);

int main(void) {
/* ----- セットアップ ----- */
    /* --- 上限値の設定 --- */
    mpz_t limit;
    mpz_init(limit);
    mpz_set_ui(limit, 2);
    mpz_pow_ui(limit, limit, 254);
    print_green_color("limit = ");
    gmp_printf ("%s%Zd\n", "", limit);

    /* --- 楕円曲線 E の生成 --- */
    EC_GROUP E;
    curve_init(E, "ec_bn254_fpa");

    /* --- 楕円曲線 E 上の点 P の生成 --- */
    EC_POINT P;
    point_init(P, E);
    point_random(P);
    print_green_color("P =  ");
    point_print(P);

    /* --- aさんの秘密鍵(a)を生成 --- */
    mpz_t a;
    mpz_init(a);
    create_mpz_t_random(a, limit);
    print_green_color("a = ");
    gmp_printf ("%s%Zd\n", "", a);

    /* --- bさんの秘密鍵(b)を生成 --- */
    mpz_t b;
    mpz_init(b);
    create_mpz_t_random(b, limit);
    print_green_color("b = ");
    gmp_printf ("%s%Zd\n", "", b);

    /* --- aさんの公開鍵(aP)を生成 --- */
    EC_POINT aP;
    point_init(aP, E);
    point_mul(aP, a, P);
    print_green_color("aP = ");
    point_print(aP);

    /* --- bさんの公開鍵(bP)を生成 --- */
    EC_POINT bP;
    point_init(bP, E);
    point_mul(bP, b, P);
    print_green_color("bP = ");
    point_print(bP);

/* ----- Encode ----- */
    /* --- 平文mとmの長さ --- */
    char m[]  = "hello_world!日本国民は、正当に選挙された国会における代表者を通じて行動し、われらとわれらの子孫のために、諸国民との協和による成果と、わが国全土にわたつて自由のもたらす恵沢を確保し、政府の行為によつて再び戦争の惨禍が起ることのないやうにすることを決意し、ここに主権が国民に存することを宣言し、この憲法を確定する。そもそも国政は、国民の厳粛な信託によるものであつて、その権威は国民に由来し、その権力は国民の代表者がこれを行使し、その福利は国民がこれを享受する。これは人類普遍の原理であり、この憲法は、かかる原理に基くものである。われらは、これに反する一切の憲法、法令及び詔勅を排除する。";
    int m_length = strlen(m);

    /* --- ランダムな値 r --- */
    mpz_t r;
    mpz_init(r);
    create_mpz_t_random(r, limit);
    print_green_color("random = ");
    gmp_printf ("%s%Zd\n", "", r);

    /* --- rP の計算 --- */
    EC_POINT rP;
    point_init(rP, E);
    point_mul(rP, r, P);
    print_green_color("rP = ");
    point_print(rP);

    /* --- rK_A の計算 --- */
    EC_POINT rK_A;
    point_init(rK_A, E);
    point_mul(rK_A, r, aP);
    print_green_color("rK_A = ");
    point_print(rK_A);

    /* --- rK_Aの文字列化 --- */
    size_t rK_A_oct_size;
    unsigned char rK_A_oct[m_length+1];
    point_to_oct(rK_A_oct, &rK_A_oct_size, rK_A);
    print_unsigned_char(rK_A_oct, "rK_A_oct", rK_A_oct_size);

    /* --- M + rK_a --- */
    unsigned char ciphertext[m_length+1];
    calculation(ADD, ciphertext, rK_A_oct, m, rK_A_oct_size, m_length);

    // Enc(M) = (rP, m + rK_A) = (rP, ciphertext) = (C1, C2)

/* ----- Decode ----- */
    /* --- aC1 --- */
    EC_POINT arP;
    point_init(arP, E);
    point_mul(arP, a, rP);
    print_green_color("arP = ");
    point_print(arP);

    /* --- arPの文字列化 --- */
    size_t arP_oct_size;
    unsigned char arP_oct[m_length+1];
    point_to_oct(arP_oct, &arP_oct_size, arP);
    print_unsigned_char(arP_oct, "arP_oct", arP_oct_size);

    /* --- C2 - aC1 --- */
    unsigned char plaintext[m_length+1];
    calculation(SUB, plaintext, arP_oct, ciphertext, arP_oct_size, m_length);
    print_green_color("結果 : ");
    printf("%s\n", plaintext);

/* ----- 領域の解放 ----- */
    mpz_clears(limit, a, b, r, NULL);
    point_clear(P);
    point_clear(aP);
    point_clear(bP);
    point_clear(rP);
    point_clear(arP);
    point_clear(rK_A);
    curve_clear(E);
    print_green_color("--- 正常終了 ---\n");
    return 0;
}

/* -----------------------------------------------
 * mpz_tでランダムな値を生成する関数
 * $0 生成した値を入れる変数
 * $1 上限値
 * 参考サイト https://sehermitage.web.fc2.com/etc/gmp_src.html
 -----------------------------------------------*/
void create_mpz_t_random(mpz_t op, const mpz_t n) {
    gmp_randstate_t state;
    gmp_randinit_default(state);

    struct timeval tv, tv2;
    gettimeofday(&tv2, NULL);

    do {
        gettimeofday(&tv, NULL);
    } while (tv.tv_usec == tv2.tv_usec);

    gmp_randseed_ui(state, tv.tv_usec);
    mpz_urandomm(op, state, n);

    gmp_randclear(state);
}

/* -----------------------------------------------
 * 演算関数
 * $0 演算モード
 * $1 計算結果を入れるu_char配列ポインタ
 * $2 XORする値
 * $3 平文/暗号化文
 * $4 ハッシュの文字数
 * $5 テキストの文字数
 -----------------------------------------------*/
void calculation(Mode mode, unsigned char *ciphertext, const unsigned char *hash,
                 const char *text, const size_t hashSize, const size_t textSize) {
    // 1文字ずつ分解し、演算する
    for(size_t i=0; i<textSize; i++){
        switch (mode) {
            case 0:
                ciphertext[i] = text[i] + hash[i%hashSize];
                break;
            case 1:
                ciphertext[i] = text[i] - hash[i%hashSize];
                break;
            case 2:
                ciphertext[i] = text[i] ^ hash[i%hashSize];
                break;
        }
    }
    ciphertext[textSize] = '\0';
    print_unsigned_char(ciphertext, "ciphertext", textSize);
}

/* -----------------------------------------------
 * unsigned char(SHA256でハッシュ化した値)を出力する関数
 * $0 出力するu_char
 * $1 データ名（出力の最初にprintされる）
 * $2 データサイズ
 -----------------------------------------------*/
void print_unsigned_char(const unsigned char *uc, const char *dataName, const size_t size){
    printf("\x1b[32m%s = \x1b[39m", dataName);
    for (size_t i=0; i<size; i++){
        printf("%02x", uc[i] );
    }
    printf("\n");
}

/* -----------------------------------------------
 * 文字列を緑色で出力する関数
 * $0 出力したい文字列
 -----------------------------------------------*/
void print_green_color(const char *text) {
    printf("\x1b[32m%s\x1b[39m", text);
}
