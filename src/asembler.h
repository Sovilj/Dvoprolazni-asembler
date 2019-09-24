//#include <stdio.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <unordered_map>
#include <map>

using namespace std;

class Asembler{

public:

    enum ScopeType {G,L};
    enum SectionType {UND,TEXT,DATA,RODATA,BSS};
    enum Directives { GLOBAL,CHAR,WORD,LONG,ALIGN,SKIP};
    enum Instructions{ADD,SUB,MUL,DIV,CMP,AND,OR,NOT,TEST,PUSH,POP,CALL,IRET,MOV,SHL,SHR,RET,JMP};
    enum Conditions{EQ,NE,GT,AL};

    struct relokacija{
        int offset;
        string tip;
        int vr;
    }Relokacija;

    
    struct instrukcija {
        int oc;
        int condition;
        int op1;
        int op1adr;
        int op2;
        int op2adr;
        int offset;
    }Instrukcija;
        
    struct sekcija{
        int offset;
        int bytes;
        instrukcija instr;
    }Sekcija;

    
    struct simbol{
        string labela;
        string sekcija;
        int offset;
        string scope;
        int redni_br;     
    }Simbol;
    struct info{
        string ime;
        int start;
        int size;
    }Info;

    static unordered_map<string,int> instruction_codes;
    static unordered_map<string,int> condition_codes;
    static unordered_map<string,int> directive_codes;
    static unordered_map<string,int> section_codes;
    static unordered_map<string,int> reg_codes;


    int start_addr;
    int location_counter;
    SectionType curr_section;
    vector<string> inFile;
    int text,data,rodata,bss;
    int text_size,data_size,rodata_size,bss_size;

    unordered_map<string,simbol> tabela_simbola;
    int redni_br_simb;
    vector<sekcija> data_sekcija;
    vector<sekcija> text_sekcija;
    vector<sekcija> rodata_sekcija;

    vector<relokacija> data_rel;
    vector<relokacija> text_rel;

    vector<info> info_sekcija;


    Asembler();
    void printWelcome();
    void initiate(ifstream& inputFile, ofstream& outputFile,int start_address);

    void load_in_file(ifstream& inputFile);    
    int prvi_prolaz();
    int drugi_prolaz();
    void load_out_file(ofstream& outFile);

    int add_symbol(string name,SectionType sec,int offset,ScopeType scope);
    int find_instr_size(string instr);
    bool is_number(const std::string& s);
    int calc1(string op1);
    int calc2(string op1,string op2);
    

    int global_check(string op);
    int obrada_direktiva(string dir, string op);
    int obrada_instrukcija(string instr_name,string op1,string op2,string condition);
    int find_section(string sekcija);
    int is_reg_dir(string op);
    void text_sekcija_add(int oc,int condition,int op1,int op1adr,int op2,int op2adr,int offset,int bytes);
    void text_rel_add(int offset,string tip,int vr);
    string find_pomeraj(string op);
    string int_to_bin(int number);
    string bin_to_hex(string bin);
    string little_endian(string s);

    int instrukcija_aritmetic(int code,int cond,string op1,string op2);
    int instrukcija_stek(int code,int cond,string op1);
    int instrukcija_jmp(string instr,int code,int cond,string op1);
    
    void print_tabela_simbola(ofstream& outFile);
    void print_info_sekcija(ofstream& outFile);
    void print_data_sekcija(ofstream& outFile);
    void print_rodata_sekcija(ofstream& outFile);
    void print_data_rel_sekcija(ofstream& outFile);
    void print_text_sekcija(ofstream& outFile);
    void print_text_rel_sekcija(ofstream& outFile);



};