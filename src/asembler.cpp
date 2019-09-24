#include "asembler.h"
#include <stdio.h>
#include <string>
#include <stdlib.h>
#include <iomanip>
#include <iostream>
#include <bitset>


unordered_map<string, int> Asembler::condition_codes =
    {
        {"eq", 0},
        {"ne", 1},
        {"gt", 2},
        {"al", 3}
    };

unordered_map<string, int> Asembler::section_codes =
    {
        {"UND", 0},
        {".text", 1},
        {".data", 2},
        {".rodata", 3},
        {".bss", 4}
    };
unordered_map<string, int> Asembler::instruction_codes =
    {
        
        {"add",  0},
        {"sub",  1},
        {"mul",  2},
        {"div",  3},
        {"cmp",  4},
        {"and",  5},
        {"or",   6},
        {"not",  7},
        {"test", 8},
        {"push", 9},
        {"pop",  10},
        {"call", 11},
        {"iret", 12},
        {"mov",  13},
        {"shl",  14},
        {"shr",  15},
        {"ret",  16},
        {"jmp",  17},
        
    };
unordered_map<string, int> Asembler::directive_codes =
    {
        {".global", 0},
        {".char", 1},
        {".word", 2},
        {".long", 3},
        {".align", 4},
        {".skip", 5}
    };
unordered_map<string, int> Asembler::reg_codes =
    {
        {"r0", 0},
        {"r1", 1},
        {"r2", 2},
        {"r3", 3},
        {"r4", 4},
        {"r5", 5},
        {"r6", 6},
        {"r7", 7},
        {"pc", 7},
        {"sp", 6}
    };

Asembler::Asembler(){
    redni_br_simb = 0;
}
void Asembler::printWelcome(){

    printf("AsemblerStart\n");
}
void Asembler::initiate(ifstream& inputFile , ofstream& outputFile ,int start_address){

    start_addr = start_address;

    load_in_file(inputFile);

  
   if( prvi_prolaz()){
       cout<< "GRESKA u prvom prolazu"<<endl;
       return;
   }

    if( drugi_prolaz()){
        cout<< "GRESKA u drugom prolazu"<<endl;
        return;
     }

    load_out_file(outputFile);
    
    cout << "End"<<endl;
    

}
void Asembler::load_in_file(ifstream& inputFile){
    
    string linija;

    while(getline(inputFile,linija)){
       
        if ( linija.size() == 0){
            continue;
        }
        string c ;
        while ( (c = linija.substr(0,1))==" "){
            linija = linija.substr(1,linija.size());
        }

        inFile.push_back(linija);

        if(linija == ".end"){
            break;
        }
    }
   /* cout<< "Ispis fajla nakon prepisivanja"<<endl;
    for(int i = 0 ; i < inFile.size() ; i++){
        cout<<inFile[i]<<endl;
    }
    */

}
int Asembler::prvi_prolaz(){
    cout << "Usao u prvi prolaz"<<endl;

    location_counter = 0;
    int i = 0;
    int offset;
    string curr_line;
    curr_section = UND;
    ScopeType scope = L;
    add_symbol("",UND,0,L);

    while(inFile[i]!= ".end"){

        curr_line = inFile[i];

        size_t t = curr_line.find(":");         //LABELA
        if ( t!=string::npos ){                   

            string lab;
            lab = curr_line.substr(0,t);

            offset = location_counter;
            if (add_symbol(lab,curr_section,offset,scope)){
                  return 1;
            };
        
            int s = curr_line.length();
            
            if ( s != (t+1))
                curr_line = curr_line.substr(t+2,s);          //odsecam labelu da nadjalje trazim instrukciju radi povecanja LC
            else{
                curr_line = inFile[++i];
                if(curr_line == ".end" || curr_line.find(":")!=string::npos){

                    cout<< "GRESKA nakon labele je potrebna odgovarajuca instrukcija"<<endl;
                    return 1;
                }
            }
            
            // sada je curr_line instrukcija i trazim njenu velicinu
           
            int instruction_size = find_instr_size(curr_line);
            if (instruction_size == -1){
                return 1;
            }
            location_counter += instruction_size;

            i++;
            continue;
        }
        t = curr_line.find(".");            // DIREKTIVA tacka oznacava direktivu  (.global ne sme u nekoj sekciji da bude)
        if ( t != string::npos){
            
            if(curr_line.find(".global")!=string::npos && curr_section!=UND){

                cout<< "GRESKA, .global direktiva mora biti na pocetku fajla"<<endl;
                return 1;

            }
            if(curr_line.find(".text")!=string::npos || curr_line.find(".data")!=string::npos || curr_line.find(".rodata")!=string::npos ||curr_line.find(".bss")!=string::npos){

                if ( !curr_line.compare(".text") ||!curr_line.compare(".data") ||!curr_line.compare(".rodata") ||!curr_line.compare(".bss")){

                    for ( int r = 0 ; r<info_sekcija.size();r++){
                        if (info_sekcija[r].ime == curr_line){
                            cout <<"GRESKA, jedna sekcija se moze pojaviti najvise jednom "<<endl;
                            return 1;
                        }
                    }
                    curr_section = (SectionType)section_codes[curr_line];
                    info in;
                    in.ime = curr_line;
                    if (info_sekcija.size() !=0 )
                        info_sekcija[info_sekcija.size()-1].size = location_counter;
                   
                    info_sekcija.push_back(in);


                    offset = 0;
                    location_counter = 0;

                    if (add_symbol(curr_line,curr_section,offset,scope)){
                        return 1;
                    };
                    i++;
                    continue;
                    

                }else{
                        cout<< "GRESKA, pocetak sekcije ne sme imati operande"<<endl;
                        return 1;

                }
                

            }
            // ako nije global u nekoj od sekcija i ako nije pocetak nove sekcije , racunam velicinu te direktive 
            int instruction_size = find_instr_size(curr_line);
            if (instruction_size == -1){
                return 1;
            }
            location_counter += instruction_size;
            i++;
            continue;

        }
                                            //  INSTRUKCIJA obicna instrukcija
        if(curr_line.find(":")==string::npos && curr_line.find(".")==string::npos){

            int instruction_size = find_instr_size(curr_line);
            if (instruction_size == -1){
                return 1;
            }
            location_counter += instruction_size;
            

        }

        i++;
    }
    info_sekcija[info_sekcija.size()-1].size = location_counter;
    int k=0;
    for( int i = 0; i<info_sekcija.size() ; i++){
        info_sekcija[i].start = start_addr + k;
        k+=info_sekcija[i].size;
    }
    //print_tabela_simbola();
    //print_info_sekcija();
   // cout << "Text:"<<text_size<<"Data:"<<data_size<<"Rodata:"<<rodata_size<<"Bss:"<<bss_size<<endl;
    cout << "Kraj prvog prolaza"<<endl;
    return 0;

}
int Asembler::find_instr_size(string instr){

    int ret= 0;

    if (instr.find(".")!=string::npos){             // ako sam nasao tacku znaci da je u pitanju direktiva
        string dir_name,dir_operand;    
        size_t d = instr.find(" ");
        if ( d != string::npos){
            dir_name = instr.substr(0,d);               //ekstraktujem ime direktive npr ".word"
            int i = instr.length();
            dir_operand = instr.substr(d+1,i);
        }else{
            dir_name = instr;
            dir_operand = "";
        }

       // cout << "Dir-name:"<< dir_name << " op:" << dir_operand<<endl;
        if ( directive_codes.find (dir_name) == directive_codes.end() ){                //proveravam da li je direktiva u listi direktiva
            cout << "GRESKA, pogresna direktiva(find_instr_size)"<<endl;
        }

        int code =  directive_codes[dir_name];          //kod direktive koji se poklapa sa enumima

        switch (code){                          //na osnovu koda radim switch i treba da vratim vrednost za koju cu pomeriti LC
            case GLOBAL:
                ret = 0;
                return ret;
            case CHAR:
                return 1;
            case WORD:
                return 2;
            case LONG:  
                return 4;
            case ALIGN:
    
                if (dir_operand.empty() || is_reg_dir(dir_operand) || !is_number(dir_operand)){
                    cout << "GRESKA , ilegalni operanadi(align)"<<dir_operand<<endl;
                    return -1;
                }else if (location_counter/stoi(dir_operand)*stoi(dir_operand) != location_counter) {   
                    if ( stoi(dir_operand)<0){
                        cout<<"GRESKA, operand negativan (align)"<<endl;
                        return -1;
                    }

                    int k = stoi(dir_operand);
                    int lc = location_counter;
                    while( lc >= k)
                        k+=k;
                    return k-lc;
                 }
                return 0;
            case SKIP:
                if (dir_operand.empty() || !is_number(dir_operand) ){
                    cout << "GRESKA , ilegalan operand(skip)"<<endl;
                    return -1;
                }
                if ((ret = stoi(dir_operand))>=0)
                    return ret;
                else {
                    cout <<"GRESKA, operand (.skip)"<<endl;
                    return -1;
                }
            default:
                cout<<"GRESKA, u kodu direktive(find_instr_size)";
                return -1;

        }
    }else{          // obicna instrukcija
        string instr_name,operand1,operand2;    
        size_t d = instr.find(" ");
        if ( d != string::npos){
            instr_name = instr.substr(0,d);               //ekstraktujem ime instrukcije npr "add"    
            int i = instr.length();

            instr = instr.substr(d+1,i);
            d = instr.find(",");
            if (d != string::npos){
                 operand1 = instr.substr(0,d);
                 operand2 = instr.substr(d+1,i);
            }else{
                 operand1 = instr.substr(0,i);
            }

        }else{
            instr_name = instr;
        }
        // skidam condition
        if ( instr_name.find("eq")!=string::npos || instr_name.find("ne")!=string::npos || instr_name.find("gt")!=string::npos || (instr_name.find("al")!=string::npos && instr_name.find("call")==string::npos) || (instr_name.find("al")!=string::npos &&instr_name.find("callal")!=string::npos) ){
            int len = instr_name.size();
            instr_name = instr_name.substr(0,len-2);
        }
       // cout << "instr-name:"<< instr_name << " op1:" << operand1 << " op2:"<< operand2 << "lc:"<<location_counter<<endl;


        if ( instruction_codes.find (instr_name) == instruction_codes.end() ){                //proveravam da li je instr u listi instr
            cout << "GRESKA, nepostojeca instrukcija(find_instr_size)(nije pronadjen code)"<<endl;
            return -1;
        }

        int code =  instruction_codes[instr_name]; 
        switch(code){
            case ADD:
                if (operand1.empty() || operand2.empty()){
                    cout << "GRESKA , nema potrebnih operanada(add)"<<endl;
                    return -1;
                }
               return calc2(operand1,operand2);

            case SUB:
                if (operand1.empty() || operand2.empty()){
                    cout << "GRESKA , nema potrebnih operanada(sub)"<<endl;
                    return -1;
                }
                return calc2(operand1,operand2);
            case MUL:
                if (operand1.empty() || operand2.empty()){
                    cout << "GRESKA , nema potrebnih operanada(mul)"<<endl;
                    return -1;
                }
                return calc2(operand1,operand2);
            case DIV:
                if (operand1.empty() || operand2.empty()){
                    cout << "GRESKA , nema potrebnih operanada(div)"<<endl;
                    return -1;
                }
                return calc2(operand1,operand2);
            case CMP:
                if (operand1.empty() || operand2.empty()){
                    cout << "GRESKA , nema potrebnih operanada(cmp)"<<endl;
                    return -1;
                }
                return calc2(operand1,operand2);
            case AND:
                if (operand1.empty() || operand2.empty()){
                    cout << "GRESKA , nema potrebnih operanada(and)"<<endl;
                    return -1;
                }
                return calc2(operand1,operand2);
            case OR:
                 if (operand1.empty() || operand2.empty()){
                    cout << "GRESKA , nema potrebnih operanada(or)"<<endl;
                    return -1;
                }
                return calc2(operand1,operand2);
            case NOT:
                if (operand1.empty() || operand2.empty()){
                    cout << "GRESKA , nema potrebnih operanada(not)"<<endl;
                    return -1;
                }
                return calc2(operand1,operand2);
            case TEST:
                if (operand1.empty() || operand2.empty()){
                    cout << "GRESKA , nema potrebnih operanada(test)"<<endl;
                    return -1;
                }
                return calc2(operand1,operand2);
            case PUSH:
                if (operand1.empty() || !operand2.empty()){
                    cout << "GRESKA , ilegalni operandi(push)"<<endl;
                    return -1;
                }
                return calc1(operand1);
            case POP:
                if (operand1.empty() || !operand2.empty()){
                    cout << "GRESKA , ilegalni operandi(pop)"<<endl;
                    return -1;
                }
                return calc1(operand1);
            case CALL:
                 if (operand1.empty() || !operand2.empty()){
                    cout << "GRESKA , ilegalni operandi(call)"<<endl;
                    return -1;
                }
                return calc1(operand1);
                         
            case IRET:
                if (!operand1.empty() || !operand2.empty()){
                    cout << "GRESKA , ilegalni operandi(iret)"<<endl;
                    return -1;
                }
                return 2;
                
            case MOV:
                if (operand1.empty() || operand2.empty()){
                    cout << "GRESKA , nema potrebnih operanada(mov)"<<endl;
                    return -1;
                }
                return calc2(operand1,operand2);
            case SHL:
                if (operand1.empty() || operand2.empty()){
                    cout << "GRESKA , nema potrebnih operanada(shl)"<<endl;
                    return -1;
                }
                return calc2(operand1,operand2);
            case SHR:
                if (operand1.empty() || operand2.empty()){
                    cout << "GRESKA , nema potrebnih operanada(shr)"<<endl;
                    return -1;
                }
                return calc2(operand1,operand2);
            case RET:
                if (!operand1.empty() || !operand2.empty()){
                    cout << "GRESKA , ilegalni operandi(ret)"<<endl;
                    return -1;
                }
                return 2;
            case JMP:
                if (operand1.empty() || !operand2.empty()){
                    cout << "GRESKA , ilegalni operandi(jmp)"<<endl;
                    return -1;
                }
                return 4;
            default:
                cout<< "GRESKA , instrukcija nije prepoznata(find_instr_size)"<<endl;

        }


    }


}
bool Asembler::is_number(const std::string& s){
    
    std::string::const_iterator it = s.begin();
    if ( s.substr(0,1) == "-"){
        it++;
    }
    while (it != s.end() && std::isdigit(*it)) ++it;
    return !s.empty() && it == s.end();
}
int Asembler::calc1(string op1){
    int ret = 4;
    if ((op1.find("r0")!=string::npos || op1.find("r1")!=string::npos || op1.find("r2")!=string::npos|| op1.find("r3")!=string::npos|| op1.find("r4")!=string::npos|| op1.find("r5")!=string::npos|| op1.find("r6")!=string::npos|| op1.find("r7")!=string::npos || op1.find("sp")!=string::npos|| op1.find("pc")!=string::npos)
    && op1.find("[")==string::npos && op1.find("*")==string::npos && op1.find("&")==string::npos){
        ret = 2;
    }
      
    return ret;
}
int Asembler::calc2(string op1,string op2){

      int  ret = 4 ;
    if ( is_number(op1) || op1.find("&")!=string::npos){
       cout << "GRESKA kod prvog operanda ilegalno adresiranje"<<endl; 
        return -1;             
    }
    // DODATI MOGUCE GRESKE
    if ( op1.find("[")==string::npos &&          //ako su oba reg.dir.
         op2.find("[")==string::npos &&
         (op1.find("r0")!=string::npos || op1.find("r1")!=string::npos || op1.find("r2")!=string::npos|| op1.find("r3")!=string::npos|| op1.find("r4")!=string::npos|| op1.find("r5")!=string::npos|| op1.find("r6")!=string::npos|| op1.find("r7")!=string::npos || op1.find("sp")!=string::npos|| op1.find("pc")!=string::npos)&&
          (op2.find("r0")!=string::npos || op2.find("r1")!=string::npos || op2.find("r2")!=string::npos|| op2.find("r3")!=string::npos|| op2.find("r4")!=string::npos|| op2.find("r5")!=string::npos|| op2.find("r6")!=string::npos|| op2.find("r7")!=string::npos || op2.find("sp")!=string::npos|| op2.find("pc")!=string::npos)    
        ){
         ret = 2;
    }       

    return ret;
}
int Asembler::add_symbol(string name,SectionType sec,int offset,ScopeType scope){

    if ( tabela_simbola.find(name)!=tabela_simbola.end()){
        cout << "GRESKA , simbol se pojavljuje drugi put"<<endl;
        return 1 ;
    }
    

    simbol simb;
    simb.labela = name;
    simb.offset = offset;
    simb.scope = scope?"L":"G";
    if ( sec==0)simb.sekcija = "UND";else if(sec==1)simb.sekcija=".text";else if(sec==2)simb.sekcija=".data";else if(sec==3)simb.sekcija=".rodata";else simb.sekcija=".bss";
    simb.redni_br = redni_br_simb;

    tabela_simbola.insert({name,simb});

    redni_br_simb++;
    
    return 0;

}
void Asembler::print_tabela_simbola(ofstream& outFile){
    outFile<<"#TABELA SIMBOLA"<<endl;
    outFile<<"Labela:\t\t"<<"Sekcija:\t"<<"Offset\t"<<"Scope\t"<<"Redni_broj\t"<<endl;
    int i = 0;
    auto iter = tabela_simbola.begin();
    while( iter != tabela_simbola.end() ){
        if ( iter->second.redni_br == i){
            outFile << iter->second.labela;
            if (iter->second.labela.size() >3)
                outFile << "\t\t";
            else
                outFile << "\t\t\t";

            outFile<<iter->second.sekcija;
            if (iter->second.sekcija.size() >3)
                outFile << "\t\t";
            else
                outFile << "\t\t\t";
            
            outFile<<std::hex<<uppercase<<setfill('0')<<setw(2)<<iter->second.offset;
            outFile<< "\t\t"<<iter->second.scope<< "\t\t"<<iter->second.redni_br <<endl;
            i++;
            iter=tabela_simbola.begin();
            continue;
        }
        ++iter;
    }
    outFile<<endl;
}
void Asembler::print_info_sekcija(ofstream& outFile){
    outFile<< "#INFO SEKCIJA: "<<endl;
    outFile<<"Start address: "<<start_addr<<endl;
    outFile<<"Ime:\t"<<"Size:\t"<<"Start:\t"<<endl;     // decimalno da bi se lakse videlo
    for( int i = 0; i<info_sekcija.size() ; i++){     
        outFile<<info_sekcija[i].ime<<"\t"<<info_sekcija[i].size<<"\t\t"<<info_sekcija[i].start<<endl;
    }
    outFile<<endl;
}
void Asembler::print_data_sekcija(ofstream& outFile){
    outFile<< "#DATA SEKCIJA: "<<endl;
    
    for( int i = 0; i<data_sekcija.size() ; i++){
        if (data_sekcija[i].bytes == 2){
            
            outFile <<std::hex <<std::setfill('0')<<std::setw(4)<<__builtin_bswap16(data_sekcija[i].offset);
           
        }else if (data_sekcija[i].bytes == 4){
            outFile <<std::hex <<std::setfill('0')<<std::setw(8)<<__builtin_bswap32(data_sekcija[i].offset);
        }else {
            outFile <<std::hex <<std::setfill('0')<<std::setw(data_sekcija[i].bytes*2)<<data_sekcija[i].offset;   
        }
            
        outFile<<" ";
    }
    outFile<<endl;
    outFile<<endl;

}
void Asembler::print_rodata_sekcija(ofstream& outFile){

    outFile<< "#RODATA SEKCIJA: "<<endl;
    
    for( int i = 0; i<rodata_sekcija.size() ; i++){
        if (rodata_sekcija[i].bytes == 2){
            outFile <<std::hex <<std::setfill('0')<<std::setw(4)<<__builtin_bswap16(rodata_sekcija[i].offset);
           
        }else if (rodata_sekcija[i].bytes == 4){
            outFile <<std::hex <<std::setfill('0')<<std::setw(8)<<__builtin_bswap32(rodata_sekcija[i].offset);
        }else{
            outFile <<std::hex <<std::setfill('0')<<std::setw(rodata_sekcija[i].bytes*2)<<rodata_sekcija[i].offset;   
        }
            
        outFile<<" ";
    }
    outFile<<endl;
    outFile<<endl;
    
}
void Asembler::print_data_rel_sekcija(ofstream& outFile){
    outFile<< "#DATA_REL SEKCIJA: "<<endl;
    outFile<< "Offset:\t\t"<<"Tip:\t"<<"Vr:\t"<<endl;               
    for( int i = 0; i<data_rel.size() ; i++){
        outFile<<hex<<setfill('0')<<setw(8)<<data_rel[i].offset;
        outFile<<"\t"<<data_rel[i].tip;
        outFile<<"\t"<<data_rel[i].vr<<endl;
    }
    outFile<<endl;
    
}
void Asembler::print_text_sekcija(ofstream& outFile){
    outFile <<"#TEXT SEKCIJA:"<<endl;

    for( int i = 0; i<text_sekcija.size() ; i++){
       string instr;
       
       instr += bitset<4>(text_sekcija[i].instr.oc).to_string();                // prva dva bajta ispisujem kako jesu 
       instr += bitset<2>(text_sekcija[i].instr.condition).to_string();
       instr += bitset<2>(text_sekcija[i].instr.op1adr).to_string();
       instr += bitset<3>(text_sekcija[i].instr.op1).to_string();
       instr += bitset<2>(text_sekcija[i].instr.op2adr).to_string();
       instr += bitset<3>(text_sekcija[i].instr.op2).to_string();

       if ( text_sekcija[i].bytes == 4){                                        // ako postoje druga dva bajta(offset)
           string temp = bitset<16>(text_sekcija[i].instr.offset).to_string();
           temp = little_endian(temp);
           instr += temp;                                                        // ispisujem ih u little endian formatu
       }
       outFile << bin_to_hex(instr);
    
       outFile<<" ";
    }
    outFile<<endl;
    outFile<<endl;
}
void Asembler::print_text_rel_sekcija(ofstream& outFile){

    outFile<<"#TEXT_REL SEKCIJA: "<<endl;
    outFile<< "Offset:\t\t"<<"Tip:\t"<<"Vr:\t"<<endl;
    for( int i = 0; i<text_rel.size() ; i++){
        outFile<<hex<<setfill('0')<<setw(8)<<text_rel[i].offset;
        outFile<<"\t"<<text_rel[i].tip;
        outFile<<"\t"<<text_rel[i].vr<<endl;
    }
    outFile<<endl;

    
}
int Asembler::drugi_prolaz(){


    cout << "Usao u drugi prolaz"<<endl;

    location_counter = 0;
    int i = 0;
    int offset;
    string curr_line;
    curr_section = UND;
    ScopeType scope = L;

    while(inFile[i]!=".end"){

        curr_line = inFile[i];
        size_t t = curr_line.find(":");           
        if (t!=string::npos){                               // nasao labelu koju treba da odsecem 
            int s = curr_line.length();            
            if ( s != (t+1))
               curr_line = curr_line.substr(t+2,s);          //odsecam labelu da nadjalje trazim instrukciju
            else{
                curr_line = inFile[++i];
                if(curr_line == ".end" || curr_line.find(":")!=string::npos){
                    cout<< "GRESKA nakon labele je potrebna odgovarajuca instrukcija"<<endl;
                    return 1;
                }
            }
            
        }
        // curr_line je sada instrukcija ili direktiva;
        t = curr_line.find(".");
        if (t!=string::npos){           //DIREKTIVA

            if ( curr_line.find(".global")!=string::npos){                  // prvo obradjujem global koji ima vise parametara
                    size_t s = curr_line.find(" ");
                    int len = curr_line.size();
                    string op1 ,op;
                    size_t k = curr_line.find(",");         // ako postoji zarez ima vise operanada(bar dva)
                    if (k!=string::npos){
                        op1 = curr_line.substr(s+1,(k-(s+1)));
                       
                        global_check(op1);     
                        
                        string rest = curr_line.substr(k+1,len);

                        size_t k=rest.find(",");
                        while(k!=string::npos){
                            int h = rest.size();
                            op = rest.substr(0,k);
                            global_check(op);
                            rest = rest.substr(k+1,h);
                            k=rest.find(",");
                        }
                        op = rest;
                        global_check(op);

                    }else{
                        op1 = curr_line.substr(s+1,len);
                        global_check(op1);
                    }
                    i++;
                    continue;
            }
            
            size_t s = curr_line.find(" ");             // direktive .char .word. .long .aling .skip koje imaju operande dakle i jedan space
            if(s != string::npos ){ 
                if( curr_section!= UND){
                    string dir = curr_line.substr(0,s);
                    string op = curr_line.substr(s+1,curr_line.size());
        
                    if(obrada_direktiva(dir,op)){          // obrada direktive (dodavanje u tabele itd)
                        return 1;
                    }                  

                    location_counter+=find_instr_size(curr_line);

                    i++;
                    continue;
                }else{
                    cout<<"GRESKA, direktiva mora biti u nekoj od sekcija"<<endl;
                    return 1;
                }
               
            }
            // Pocetak nove sekcije
            if (curr_line.find(".text")!=string::npos || curr_line.find(".data")!=string::npos || curr_line.find(".rodata")!=string::npos ||curr_line.find(".bss")!=string::npos){

                curr_section = (SectionType)section_codes[curr_line];

                location_counter = 0;

                i++;
                continue;
            }
        
        }
        // odsecena labela ; nije pronadjena "."" u instrukciji znaci nije ni direktiva onda je instrukcija

        string instr_name,operand1,operand2;  
        string rest;
        string condition;  
        size_t d = curr_line.find(" ");
        if ( d != string::npos){
            instr_name = curr_line.substr(0,d);               //ekstraktujem ime instrukcije npr "addeq"  "popgt" "sub"
            int i = curr_line.length();

            rest = curr_line.substr(d+1,i);
            d = rest.find(",");                         // ako postoji zarez znaci 2 su operanda ako ne 1 operand
            if (d != string::npos){
                 operand1 = rest.substr(0,d);
                 operand2 = rest.substr(d+1,i);
            }else{
                 operand1 = rest.substr(0,i);
                 operand2 = "";
            }

        }else{
            instr_name = curr_line;
            operand1 = "";
            operand2 = "";
        }
        // skidam condition
        if ( instr_name.find("eq")!=string::npos || instr_name.find("ne")!=string::npos || instr_name.find("gt")!=string::npos || (instr_name.find("al")!=string::npos && instr_name.find("call")==string::npos) || (instr_name.find("al")!=string::npos &&instr_name.find("callal")!=string::npos) ){
            int len = instr_name.size();
            condition = instr_name.substr(len-2,2);
            instr_name = instr_name.substr(0,len-2);
        }else {
            condition = "al";
        }
        //cout << "instr-name:"<< instr_name << " op1:" << operand1 << " op2:"<< operand2 <<endl;


        if ( (instruction_codes.find(instr_name) == instruction_codes.end()) ||(condition_codes.find(condition) == condition_codes.end()) ){     
                                                                             //proveravam da li je instr u listi instr i condition na listi condition-a
            cout << "GRESKA, pogresna instrukcija(drugi prolaz)(codes)";
            return 1;
        }

        if (curr_section == TEXT){
            if( obrada_instrukcija(instr_name,operand1,operand2,condition)){
                    cout <<"GRESKA ,obrada_instrukcija(drugi prolaz)"<<endl;
                    return 1;
            }
            location_counter+= find_instr_size(curr_line);

        }else{
            cout << "Masinski kod mora biti u text sekciji"<<endl;
            return 1;
        }
        
        


        i++;

        

    }

    /*print_data_sekcija();
    print_rodata_sekcija();
    print_data_rel_sekcija();
    print_text_sekcija();
    print_text_rel_sekcija();
    print_tabela_simbola();*/
    cout<<"Kraj drugog prolaza"<<endl;
    return 0;
}
int Asembler::obrada_direktiva(string dir,string op){
        
        if ( directive_codes.find (dir) == directive_codes.end() ){                //proveravam da li je direktiva u listi direktiva
                cout << "GRESKA, pogresna direktiva(nije pronadjena direktiva)"<<endl;
                return 1;
        }

        int code =  directive_codes[dir];  
        
        
        switch (code){                          
            case GLOBAL:            // vec je obradjen global
                break;
            case CHAR:
                if ( is_number(op) && !op.empty() && stoi(op)<=255 && stoi(op)>=0){            // char moze samo neposrednu vrednost da ima kao operand
                    if (curr_section == RODATA){
                        sekcija sek ;
                        sek.bytes = 1;
                        sek.offset = stoi(op);
                        rodata_sekcija.push_back(sek);

                    }else if(curr_section == DATA){
                        sekcija sek;
                        sek.bytes = 1;
                        sek.offset = stoi(op);
                        data_sekcija.push_back(sek);

                    }else {
                        cout<<"GRESKA, .char direktiva ne sme biti u .text i .bss sekciji"<<endl;
                        return 1;
                    }
                }else{
                    cout << "GRESKA,operand .char sekcije mora biti ascii broj"<<endl;
                    return 1;
                }
                return 0;
                
            case WORD:      // u word moze da stane i neposredna vr i simbol/adresa 
                if ( is_number(op) && !op.empty()){                     // neposredna vrednost 
                    if (curr_section == RODATA){
                        sekcija sek ;
                        sek.bytes = 2;
                        sek.offset = stoi(op);
                        rodata_sekcija.push_back(sek);
                    }else if(curr_section == DATA){
                        sekcija sek;
                        sek.bytes = 2;
                        sek.offset = stoi(op);
                        data_sekcija.push_back(sek);
                    }else {
                        cout<<"GRESKA, .word direktiva ne sme biti u .text i .bss sekciji(.word)"<<endl;
                        return 1;
                    }

                }else if(!is_number(op)&&!is_reg_dir(op) && !op.empty() && curr_section== DATA && op.find("&")==string::npos && op.find("*")==string::npos && op.find("$")==string::npos && op.find("[")==string::npos){          
                                                                                                     // simbol 

                       if(tabela_simbola.find(op)!=tabela_simbola.end()){
                           simbol sim = tabela_simbola.find(op)->second;
                           sekcija sek;
                           sek.bytes=2;
                           sek.offset=sim.offset;
                           data_sekcija.push_back(sek);
                           relokacija rel;
                           rel.offset = location_counter;
                           rel.tip = "R_386_16";
                           if ( sim.scope == "L")
                                rel.vr = find_section(sim.sekcija);
                            else 
                                rel.vr = sim.redni_br;
                           data_rel.push_back(rel);

                       }else{
                            cout << "GRESKA , nepostojeci/nekorektan simbol(.word)"<<endl;
                            return 1;
                       }

                }else if (!is_number(op) && !op.empty() && curr_section== DATA && op.find("&")!=string::npos){             
                     // &simbol (adresa)
                    string labela = op.substr(1,op.size());
                    if (tabela_simbola.find(labela)!=tabela_simbola.end()){
                        simbol simb = tabela_simbola.find(labela)->second;
                        sekcija sek;
                        sek.bytes = 2;
                        sek.offset =simb.offset;
                        data_sekcija.push_back(sek);
                        relokacija rek ;
                        rek.tip = "R_386_16";
                        if ( simb.scope == "L")
                            rek.vr = find_section(simb.sekcija);
                        else
                            rek.vr = simb.redni_br;
                        rek.offset = location_counter;
                        data_rel.push_back(rek);

                    }else{
                            cout << "GRESKA , nepostojeci/nekorektan &simbol(.word)"<<endl;
                            return 1;
                    }



                }else {
                    cout <<"GRESKA, nedozvoljeno adresiranje (.word)"<<endl;
                }
                return 0;
            
            case LONG:  
                 if ( is_number(op) && !op.empty()){                     // neposredna vrednost 
                    if (curr_section == RODATA){
                        sekcija sek ;
                        sek.bytes = 4;
                        sek.offset = stoi(op);
                        rodata_sekcija.push_back(sek);
                    }else if(curr_section == DATA){
                        sekcija sek;
                        sek.bytes = 4;
                        sek.offset = stoi(op);
                        data_sekcija.push_back(sek);
                    }else {
                        cout<<"GRESKA, .long direktiva ne sme biti u .text i .bss sekciji(.long)"<<endl;
                        return 1;
                    }

                }else if(!is_number(op) && !op.empty() && curr_section== DATA &&!is_reg_dir(op)  && op.find("&")==string::npos && op.find("*")==string::npos && op.find("$")==string::npos && op.find("[")==string::npos){                      
                            // simbol 

                       if(tabela_simbola.find(op)!=tabela_simbola.end()){
                           simbol sim = tabela_simbola.find(op)->second;
                           sekcija sek;
                           sek.bytes=4;
                           relokacija rel;
                           rel.offset = location_counter;
                           rel.tip = "R_386_16";

                           if ( sim.scope == "G"){
                                sek.offset=sim.offset;
                                data_sekcija.push_back(sek);
                                rel.vr = sim.redni_br;
                           }else {
                                sek.offset=sim.offset;
                                data_sekcija.push_back(sek);
                                rel.vr = find_section(sim.sekcija);
                           }
                            data_rel.push_back(rel);

                       }else{
                            cout << "GRESKA , nepostojeci/nekorektan simbol(.long)"<<endl;
                            return 1;
                       }

                }else if (!is_number(op) && !op.empty() && curr_section== DATA && op.find("&")!=string::npos){             
                     // &simbol (adresa)
                    string labela = op.substr(1,op.size());
                    if (tabela_simbola.find(labela)!=tabela_simbola.end()){
                        simbol simb = tabela_simbola.find(labela)->second;
                        sekcija sek;
                        sek.bytes = 4;
                        sek.offset =simb.offset;
                        data_sekcija.push_back(sek);
                        relokacija rek ;
                        rek.tip = "R_386_16";
                        if ( simb.scope == "L")
                            rek.vr = find_section(simb.sekcija);
                        else
                            rek.vr = simb.redni_br;
                        rek.offset = location_counter;
                        data_rel.push_back(rek);

                    }else{
                            cout << "GRESKA , nepostojeci/nekorektan &simbol(.word)"<<endl;
                            return 1;
                    }



                }else{
                    cout << "GRESKA, nedozvoljeno adresiranje (.long)"<<endl;
                    return 1;
                }
                return 0;
            case ALIGN:
            // u prvom prolazu
                return 0;
            case SKIP:
            
                if (op.empty() ){
                    cout << "GRESKA , nema potrebnih operanada(.skip)"<<endl;
                    return 1;
                }else   if ( curr_section == RODATA || curr_section== TEXT){                // da li sme ili ne sme u data .skip sekcija ??
                    cout << "GRESKA , direktiva .skip je u pogresnoj sekciji"<<endl;
                    return 1;

                }else if (is_number(op) && curr_section==DATA ){
                   
                    if ( stoi(op)>=0){
                        sekcija sek;
                        sek.offset = 0;
                        sek.bytes = stoi(op);
                        data_sekcija.push_back(sek);
                    }else {
                        cout << "GRESKA, los operand -(.skip)"<<endl;
                        return 1;
                    }

                }else if( curr_section == BSS) {
                    break;  // f-ja find_inst_size dodaje na LC vrednost ove direktive

                }else{
                    cout << "GRESKA, los operand (.skip)"<<endl;
                    return 1;
                }

                return 0;

            default:
                cout<<"GRESKA, u kodu direktive(obrada_direktiva)";
                return 11;

        }
        return 0;
}
int Asembler::obrada_instrukcija(string instr_name,string op1,string op2, string condition){

    int code =  instruction_codes[instr_name]; 
    int cond = condition_codes[condition];
    string instr = instr_name + condition +" "+ op1;

    switch(code){

        case ADD:
            if ( instrukcija_aritmetic(code,cond,op1,op2)){
                return 1;
            }
            break;
        case SUB:
            if ( instrukcija_aritmetic(code,cond,op1,op2)){
                return 1;
            }
            break;
        case MUL:
            if ( instrukcija_aritmetic(code,cond,op1,op2)){
                return 1;
            } 
            break;
        case DIV:
            if ( instrukcija_aritmetic(code,cond,op1,op2)){
                return 1;
            } 
            break;
        case CMP:
            if ( instrukcija_aritmetic(code,cond,op1,op2)){
                return 1;
            }
            break;
        case AND:
            if ( instrukcija_aritmetic(code,cond,op1,op2)){
                return 1;
            } 
            break;  
        case OR:
            if ( instrukcija_aritmetic(code,cond,op1,op2)){
                return 1;
            }    
            break;
        case NOT:
            if ( instrukcija_aritmetic(code,cond,op1,op2)){
                return 1;
            }
            break;
        case TEST:
            if ( instrukcija_aritmetic(code,cond,op1,op2)){
                return 1;
            }
            break;
        case PUSH:
            if(instrukcija_stek(code,cond,op1)){
                    return 1;
            }
            break;
        case POP:
            if(instrukcija_stek(code,cond,op1)){
                    return 1;
            }
            break;
        case CALL:// ima samo 1 operand koji treba da se smesti u pc prakticno je to skok na potprogram

            if(!is_number(op1) && op1.find("&")==string::npos && op1.find("*")==string::npos && op1.find("[")==string::npos && op1.find("$")==string::npos){
                                                                // mem.dir
                if(tabela_simbola.find(op1)!= tabela_simbola.end()){
                    simbol simb = tabela_simbola[op1];
                    if ( simb.scope == "L"){
                        text_sekcija_add(code,cond,-1,2,-1,-1,simb.offset,4);
                        text_rel_add(location_counter+2,"R_386_PC16",find_section(simb.sekcija));
                    }else{
                        text_sekcija_add(code,cond,-1,2,-1,-1,simb.offset,4);
                        text_rel_add(location_counter+2,"R_386_PC16",simb.redni_br);
                    }

                }else{
                    cout <<"GRESKA , nedefinisan simbol(call)(mem.dir)"<<endl;
                    return 1;
                }

            }else  if (op1.find("&")!=string::npos){ 
                                    // &a
                if (tabela_simbola.find(op1.substr(1,op1.size()))!= tabela_simbola.end()){
                    simbol simb = tabela_simbola[op1.substr(1,op1.size())];
                    int offset_rel = location_counter + 2;
                    int next_instr = location_counter + find_instr_size(instr);

                    if ( simb.scope == "G"){
                        int offset = -2;
                        text_sekcija_add(instruction_codes["mov"],cond,reg_codes["pc"],1,-1,0,offset,4);
                        text_rel_add(offset_rel,"R_386_PC16",simb.redni_br);

                    }else{
                        int offset = abs(simb.offset-next_instr);
                        text_sekcija_add(instruction_codes["mov"],cond,reg_codes["pc"],1,-1,0,offset,4);
                        text_rel_add(offset_rel,"R_386_PC16",find_section(simb.sekcija));
                    
                    }
                    
                }else{
                    cout <<"GRESKA, nedefinisan simbol(call)(&)"<<endl;
                    return 1;
                }

            }else{
            cout<<"GRESKA, pogresno adresiranje kod call instr"<<endl;
            }
            break;
                
        case IRET:
            if(op1.size() == 0 && op2.size() == 0){

                text_sekcija_add(code,cond,-1,-1,-1,-1,0,2);

            }else {
                cout <<"GRESKA , iret instrukcija ne treba da ima operande(iret)"<<endl;
                return 1;
            }
            break;

        case MOV:       
            if ( instrukcija_aritmetic(code,cond,op1,op2)){
                return 1;
            }
            break;
        case SHL:
            if ( instrukcija_aritmetic(code,cond,op1,op2)){
                return 1;
            }
            break;
        case SHR:
            if ( instrukcija_aritmetic(code,cond,op1,op2)){
                return 1;
            }
            break;
        case RET:   // vracanje iz potprograma znaci u pc upisujemo sa steka "pop pc"
            if(instrukcija_stek(instruction_codes["pop"],cond,"pc")){
                    return 1;
            }
            break;
        case JMP:
            if ( instrukcija_jmp(instr,code,cond,op1)){
                    return 1;
            }
            break;
        default:
            cout<< "GRESKA , instrukcija nije prepoznata(obrada_instrukcija)"<<endl;
    }
    return 0;

}
int Asembler::global_check(string op){

    simbol simb;
     if(tabela_simbola.find(op)!=tabela_simbola.end()){         // ako je simbol vec u tabeli promenim L u G
         if ( tabela_simbola.find(op)->second.scope == "L" )
            tabela_simbola.find(op)->second.scope = "G";
     }else{                                                     // ako nije u tabeli treba ga dodati ( UND , 0 , G )
        add_symbol(op,UND,0,G);

     }
    return 0;
}
int Asembler::find_section(string sekcija){
    if (tabela_simbola.find(sekcija)!=tabela_simbola.end()){
        return tabela_simbola.find(sekcija)->second.redni_br;
    }
    cout << "GRESKA , nepostojeca sekcija(find_section)";
    return -1;
}
int Asembler::is_reg_dir(string op1){

    if ( op1.find("[")==string::npos &&   op1.find("]")==string::npos  &&  
         (op1.find("r0")!=string::npos || op1.find("r1")!=string::npos || op1.find("r2")!=string::npos|| op1.find("r3")!=string::npos|| op1.find("r4")!=string::npos|| op1.find("r5")!=string::npos|| op1.find("r6")!=string::npos|| op1.find("r7")!=string::npos || op1.find("sp")!=string::npos|| op1.find("pc")!=string::npos)
          ){
         return 1;
    }    
    return 0;
}
void Asembler::text_sekcija_add(int oc,int condition,int op1,int op1adr,int op2,int op2adr,int offset,int bytes){

    instrukcija instr;
    sekcija sek;
    instr.oc = oc;
    instr.condition = condition;
    instr.op1 = op1;
    instr.op1adr = op1adr;
    instr.op2 = op2;
    instr.op2adr = op2adr;
    instr.offset = offset;
    sek.bytes = bytes;
    sek.instr = instr;
    sek.offset = offset;

    text_sekcija.push_back(sek);

}
void Asembler::text_rel_add(int offset,string tip,int vr){

    relokacija rel;
    rel.offset = offset;
    rel.tip = tip;
    rel.vr = vr;

    text_rel.push_back(rel);
}
string Asembler::find_pomeraj(string op){

    string ret;
    size_t i = op.find("[");
    size_t j = op.find("]");
    ret = op.substr(i+1,(j-(i+1)));
    return ret;
}

int Asembler::instrukcija_aritmetic(int code,int cond,string op1,string op2){

    if ( is_reg_dir(op1) && is_reg_dir(op2)){           // OBA REG.DIR.

        text_sekcija_add(code,cond,reg_codes[op1],1,reg_codes[op2],1,0,2);

    }else if(is_reg_dir(op1) && !is_reg_dir(op2)){      // PRVI REG.DIR DRUGI NESTO DRUGO
        
        if(is_number(op2)){                             // reg.dir. + neposredno
            text_sekcija_add(code,cond,reg_codes[op1],1,-1,0,stoi(op2),4);
        }
        
        else if(op2.find("&")!=string::npos ){          // reg.dir. + adresa simbola
            if(tabela_simbola.find(op2.substr(1,string::npos))!= tabela_simbola.end()){
                 simbol simb = tabela_simbola[op2.substr(1,string::npos)];
                if ( simb.scope == "L"){
                    text_sekcija_add(code,cond,reg_codes[op1],1,-1,0,simb.offset,4);
                    text_rel_add(location_counter+2,"R_386_16",find_section(simb.sekcija));       // localan: offset i sekcija
                }else{
                    text_sekcija_add(code,cond,reg_codes[op1],1,-1,0,simb.offset,4);            // globalan: offset i simbol
                    text_rel_add(location_counter+2,"R_386_16",simb.redni_br);
                }

            }else{
                cout <<"GRESKA , nedefinisan simbol(&)(reg.dir.+adresa.simb)"<<endl;
                return 1;
            }

        }else if(!is_number(op2) && op2.find("&")==string::npos && op2.find("*")==string::npos && op2.find("[")==string::npos && op2.find("$")==string::npos){
                                                                // reg.dir. + mem.dir
            if(tabela_simbola.find(op2)!= tabela_simbola.end()){
                simbol simb = tabela_simbola[op2];
                if ( simb.scope == "L"){
                    text_sekcija_add(code,cond,reg_codes[op1],1,-1,2,simb.offset,4);
                    text_rel_add(location_counter+2,"R_386_16",find_section(simb.sekcija));
                }else{
                    text_sekcija_add(code,cond,reg_codes[op1],1,-1,2,simb.offset,4);
                    text_rel_add(location_counter+2,"R_386_16",simb.redni_br);
                }

            }else{
                cout <<"GRESKA , nedefinisan simbol(reg.dir.+mem.dir)"<<endl;
                return 1;
            }

        }else if(op2.find("*")!=string::npos && is_number(op2.substr(1,op2.size()))){
                                                                // reg.dir. + lokacija sa adrese (*20)
             text_sekcija_add(code,cond,reg_codes[op1],1,-1,2,stoi(op2.substr(1,op2.size())),4);

        }else if(op2.find("[")!=string::npos && op2.find("]")!= string::npos && reg_codes.find(op2.substr(0,2))!=reg_codes.end()){
                                                                // reg.dir. + reg.ind.

             string pomeraj = find_pomeraj(op2);
            
                if ( is_number(pomeraj)){
                    text_sekcija_add(code,cond,reg_codes[op1],1,reg_codes[op2.substr(0,2)],3,stoi(pomeraj),4);

                }else{
                    if(tabela_simbola.find(pomeraj)!= tabela_simbola.end()){
                        simbol simb = tabela_simbola[pomeraj];
                        if ( simb.scope == "L"){
                            text_sekcija_add(code,cond,reg_codes[op1],1,reg_codes[op2.substr(0,2)],3,simb.offset,4);
                            text_rel_add(location_counter+2,"R_386_16",find_section(simb.sekcija));
                        }else{
                            text_sekcija_add(code,cond,reg_codes[op1],1,reg_codes[op2.substr(0,2)],3,simb.offset,4);
                            text_rel_add(location_counter+2,"R_386_16",simb.redni_br);
                        }
                    }else{
                        cout <<"GRESKA, nedefinisan simbol(reg.dir.+reg.ind)"<<endl;
                    }

                }
        }else {

            cout << "GRESKA , ilegalno adresiranje(reg.dir + other)"<<op1<<" "<<op2<<endl;
            return 1;
        }


    }// kraj -> reg.dir. +neko drugo adresiranje        // PRVI NESTO DRUGI REG.DIR.
    else if(!is_reg_dir(op1) && is_reg_dir(op2)){
        if(!is_number(op1) && op1.find("&")==string::npos && op1.find("*")==string::npos && op1.find("[")==string::npos && op1.find("$")==string::npos){
                                                                // mem.dir. + reg.dir
            if(tabela_simbola.find(op1)!= tabela_simbola.end()){
                simbol simb = tabela_simbola[op1];
                if ( simb.scope == "L"){
                    text_sekcija_add(code,cond,-1,2,reg_codes[op2],1,simb.offset,4);
                    text_rel_add(location_counter+2,"R_386_16",find_section(simb.sekcija));
                }else{
                    text_sekcija_add(code,cond,-1,2,reg_codes[op2],1,simb.offset,4);
                    text_rel_add(location_counter+2,"R_386_16",simb.redni_br);
                }

            }else{
                cout <<"GRESKA , nedefinisan simbol(mem.dir+reg.dir)"<<endl;
                return 1;
            }

        }else if(op1.find("*")!=string::npos && is_number(op1.substr(1,op1.size()))){
                                                                // lokacija sa adrese + reg.dir;
            text_sekcija_add(code,cond,-1,2,reg_codes[op2],1,stoi(op1.substr(1,op1.size())),4);

        }else if(op1.find("[")!=string::npos && op1.find("]")!= string::npos && reg_codes.find(op1.substr(0,2))!=reg_codes.end()){
            string pomeraj = find_pomeraj(op1);                 // reg.ind. +reg.dir;
                if ( is_number(pomeraj)){
                    text_sekcija_add(code,cond,reg_codes[op1.substr(0,2)],3,reg_codes[op2],1,stoi(pomeraj),4);

                }else{
                    if(tabela_simbola.find(pomeraj)!= tabela_simbola.end()){
                        simbol simb = tabela_simbola[pomeraj];
                        if ( simb.scope == "L"){
                            text_sekcija_add(code,cond,reg_codes[op1.substr(0,2)],3,reg_codes[op2],1,simb.offset,4);
                            text_rel_add(location_counter+2,"R_386_16",find_section(simb.sekcija));
                        }else{
                            text_sekcija_add(code,cond,reg_codes[op1.substr(0,2)],3,reg_codes[op2],1,simb.offset,4);
                            text_rel_add(location_counter+2,"R_386_16",simb.redni_br);
                        }
                    }else{
                        cout <<"GRESKA, nedefinisan simbol(reg.ind+reg.dir)"<<endl;
                    }

                }
            
        }else {
            cout <<"GRESKA, ilegalno adresiranje(other+reg.dir)"<<op1<<op2<<endl;
        }

    }
    else {
        cout <<"GRESKA, ilegalno adresiranje(arithmetic_instr)"<<op1<<" "<<op2<<endl;
        return 1;
    }
    return 0;

}

int Asembler::instrukcija_stek(int code,int cond,string op1){

    switch(code){

        case PUSH:          // operand mi je src i njega treba smestiti na stek
            if (is_number(op1)){                                        // neposredna vr.
                text_sekcija_add(code,cond,-1,0,-1,-1,stoi(op1),4);

            }else if(op1.find("&")!=string::npos){                      // adresa simbola &
                if (tabela_simbola.find(op1.substr(1,op1.size()))!=tabela_simbola.end()){

                    simbol simb = tabela_simbola[op1.substr(1,op1.size())];
                    text_sekcija_add(code,cond,-1,0,-1,-1,simb.offset,4);
                    if (simb.scope == "L")
                        text_rel_add(location_counter+2,"R_386_16",find_section(simb.sekcija));
                    else
                        text_rel_add(location_counter+2,"R_386_16",simb.redni_br);
                }else{
                    cout<<"GRESKA , nedefinisan simbol(push)"<<endl;
                    return 1;
                }
            }else if(op1.find("&")==string::npos && op1.find("*")==string::npos && op1.find("$")==string::npos && op1.find("[")==string::npos && !is_number(op1) && !is_reg_dir(op1)){
                                                                        // mem dir.
                if (tabela_simbola.find(op1)!=tabela_simbola.end()){

                        simbol simb = tabela_simbola[op1];
                        text_sekcija_add(code,cond,-1,2,-1,-1,simb.offset,4);
                    if (simb.scope == "L")
                        text_rel_add(location_counter+2,"R_386_16",find_section(simb.sekcija));
                    else
                        text_rel_add(location_counter+2,"R_386_16",simb.redni_br);
                }else{
                    cout<<"GRESKA , nedefinisan simbol(push)"<<endl;
                    return 1;
                }
            }
            else if(op1.find("*")!=string::npos){                       // lokacija sa adrese *20

                    text_sekcija_add(code,cond,-1,2,-1,-1,stoi(op1.substr(1,op1.size())),4);

            }
            else if(is_reg_dir(op1)){                                   //reg.dir

                text_sekcija_add(code,cond,reg_codes[op1],1,-1,-1,0,2);

            }else if(op1.find("[")!= string::npos && op1.find("]")!= string::npos){
                                                                        //reg.ind
                string pomeraj= find_pomeraj(op1);
                if ( is_number(pomeraj)){

                        text_sekcija_add(code,cond,reg_codes[op1.substr(0,2)],3,-1,-1,stoi(pomeraj),4);
                }else{
                    if(tabela_simbola.find(pomeraj)!=tabela_simbola.end()){
                        simbol simb = tabela_simbola[pomeraj];
                        text_sekcija_add(code,cond,reg_codes[op1.substr(0,2)],3,-1,-1,simb.offset,4);
                        if (simb.scope == "L"){
                            text_rel_add(location_counter+2,"R_386_16",find_section(simb.sekcija));
                        }else{
                            text_rel_add(location_counter+2,"R_386_16",simb.redni_br);
                        }
                    }else{
                        cout << "GRESKA, nedefinisan simbol(push)"<<endl;
                    }
                }
            }else{
                cout << "GRESKA, ilegalno adresiranje(push)"<<op1<<endl;;
                return 1;
            }

            break;
        case POP:           // operand mi je destinacija znaci u nju smestam nesto 

            if(op1.find("&")==string::npos && op1.find("*")==string::npos && op1.find("$")==string::npos && op1.find("[")==string::npos && !is_number(op1) && !is_reg_dir(op1)){
                                                            //mem dir.
                if (tabela_simbola.find(op1)!=tabela_simbola.end()){

                        simbol simb = tabela_simbola[op1];
                        text_sekcija_add(code,cond,-1,2,-1,-1,simb.offset,4);
                    if (simb.scope == "L")
                        text_rel_add(location_counter+2,"R_386_16",find_section(simb.sekcija));
                    else
                        text_rel_add(location_counter+2,"R_386_16",simb.redni_br);
                }else{
                    cout<<"GRESKA , nedefinisan simbol(pop)"<<endl;
                    return 1;
                }
            }else if(op1.find("*")!=string::npos){             // lok sa adr *20
                    
                    text_sekcija_add(code,cond,-1,2,-1,-1,stoi(op1.substr(1,op1.size())),4);

            }else if(is_reg_dir(op1)){                          // reg.dir

                    text_sekcija_add(code,cond,reg_codes[op1],1,-1,-1,0,2);

            }else if(op1.find("[")!= string::npos && op1.find("]")!= string::npos){
                                                                // reg.ind.
                    
                    string pomeraj= find_pomeraj(op1);
                    if ( is_number(pomeraj)){

                        text_sekcija_add(code,cond,reg_codes[op1.substr(0,2)],3,-1,-1,stoi(pomeraj),4);
                    }else{
                        if(tabela_simbola.find(pomeraj)!=tabela_simbola.end()){
                            simbol simb = tabela_simbola[pomeraj];
                            text_sekcija_add(code,cond,reg_codes[op1.substr(0,2)],3,-1,-1,simb.offset,4);
                            if (simb.scope == "L"){
                                text_rel_add(location_counter+2,"R_386_16",find_section(simb.sekcija));
                            }else{
                                text_rel_add(location_counter+2,"R_386_16",simb.redni_br);
                            }
                        }else{
                            cout << "GRESKA, nedefinisan simbol(pop)"<<endl;
                        }
                    }
            }else {
                cout <<"GRESKA, ilegalan operand (pop)"<<endl;
                return 1;
            }

            break;

        default :
            cout <<"GRESKA, pogresna instrukcija(push pop)"<<endl;
            return 1;
    }
    return 0;
}
int Asembler::instrukcija_jmp(string instr,int code,int cond,string op1){

    if (!is_reg_dir(op1) &&!is_number(op1) && op1.find("$")==string::npos && op1.find("*")==string::npos && op1.find("&")==string::npos && op1.find("[")==string::npos){ 
                                    //mem dir. MOV pc = src
        
        if (tabela_simbola.find(op1)!= tabela_simbola.end()){
            simbol simb = tabela_simbola[op1];
            int offset_rel = location_counter + 2;
            int next_instr = location_counter + find_instr_size(instr);

            if ( simb.scope == "G"){
                int offset = -2;
                text_sekcija_add(instruction_codes["mov"],cond,reg_codes["pc"],1,-1,2,offset,4);
                text_rel_add(offset_rel,"R_386_PC16",simb.redni_br);

            }else{
                int offset = abs(simb.offset-next_instr);
                text_sekcija_add(instruction_codes["mov"],cond,reg_codes["pc"],1,-1,2,offset,4);
                text_rel_add(offset_rel,"R_386_PC16",find_section(simb.sekcija));
               
            }
            
        }else{
            cout <<"GRESKA, nedefinisan simbol(jmp) (mem.dir)"<<endl;
            return 1;
        }

    }else if(op1.find("$")!=string::npos){  // pc rel. add pc = pc + src;

        if (tabela_simbola.find(op1.substr(1,op1.size()))!= tabela_simbola.end()){
            simbol simb = tabela_simbola[op1.substr(1,op1.size())];
            int offset_rel = location_counter + 2;
            int next_instr = location_counter + find_instr_size(instr);

            if ( simb.scope == "G"){
                int offset = -2;
                text_sekcija_add(instruction_codes["add"],cond,reg_codes["pc"],1,-1,2,offset,4);
                text_rel_add(offset_rel,"R_386_PC16",simb.redni_br);

            }else{
                if( simb.sekcija != ".text"){
                    int offset = abs(simb.offset-next_instr);
                    text_sekcija_add(instruction_codes["add"],cond,reg_codes["pc"],1,-1,2,offset,4);
                    text_rel_add(offset_rel,"R_386_PC16",find_section(simb.sekcija));
                }else{
                    int offset = simb.offset - location_counter;
                    text_sekcija_add(instruction_codes["add"],cond,reg_codes["pc"],1,-1,2,offset,4);
                }
                
            }
        }else{
            cout <<"GRESKA, nedefinisan simbol(jmp)(pc rel)"<<endl;
            return 1;
        }
    }else if (op1.find("&")!=string::npos){ 
                                    // &a
        if (tabela_simbola.find(op1.substr(1,op1.size()))!= tabela_simbola.end()){
            simbol simb = tabela_simbola[op1.substr(1,op1.size())];
            int offset_rel = location_counter + 2;
            int next_instr = location_counter + find_instr_size(instr);

            if ( simb.scope == "G"){
                int offset = -2;
                text_sekcija_add(instruction_codes["mov"],cond,reg_codes["pc"],1,-1,0,offset,4);
                text_rel_add(offset_rel,"R_386_PC16",simb.redni_br);

            }else{
                int offset = abs(simb.offset-next_instr);
                text_sekcija_add(instruction_codes["mov"],cond,reg_codes["pc"],1,-1,0,offset,4);
                text_rel_add(offset_rel,"R_386_PC16",find_section(simb.sekcija));
               
            }
            
        }else{
            cout <<"GRESKA, nedefinisan simbol (jmp)(&)"<<endl;
            return 1;
        }

    }else if (is_number(op1)){ 
                                    // neposredno mov pc,20
            text_sekcija_add(instruction_codes["mov"],cond,reg_codes["pc"],1,-1,0,stoi(op1),4);
            

    }else if (op1.find("*")!=string::npos){ 
                                    // mem neposredno mov pc,*20
            if (is_number(op1.substr(1,op1.size())))
                text_sekcija_add(instruction_codes["mov"],cond,reg_codes["pc"],1,-1,2,stoi(op1.substr(1,op1.size())),4);
            else{
                cout <<"GRESKA , pogresno adresiranje (jmp)(*)"<<endl;
                return 1;
            }

    }else if (is_reg_dir(op1)){ 
                                    // reg.dir mov pc = r0
            text_sekcija_add(instruction_codes["mov"],cond,reg_codes["pc"],1,reg_codes[op1],1,0,2);
            

    }else if(op1.find("[")!= string::npos && op1.find("]")!= string::npos){
                                                                        //reg.ind
                string pomeraj= find_pomeraj(op1);
                if ( is_number(pomeraj)){   // mov pc,r1[32]

                        text_sekcija_add(instruction_codes["mov"],cond,reg_codes["pc"],1,reg_codes[op1.substr(0,2)],3,stoi(pomeraj),4);
                }else{
                    if(tabela_simbola.find(pomeraj)!=tabela_simbola.end()){ // mov pc,r1[a]
                        simbol simb = tabela_simbola[pomeraj];
                        text_sekcija_add(instruction_codes["mov"],cond,reg_codes["pc"],1,reg_codes[op1.substr(0,2)],3,simb.offset,4);
                        if (simb.scope == "L"){
                            text_rel_add(location_counter+2,"R_386_16",find_section(simb.sekcija));
                        }else{
                            text_rel_add(location_counter+2,"R_386_16",simb.redni_br);
                        }
                    }else{
                        cout << "GRESKA, nedefinisan simbol (jmp)(reg.ind)"<<endl;
                    }
                }
    }else{

        cout << "GRESKA,ilegalno adresiranje (jmp instr)"<<op1<<endl;
        return 1;

    }
    return 0;
}

void Asembler::load_out_file(ofstream& output){

    if (!info_sekcija.empty())
        print_info_sekcija(output);
    
    print_tabela_simbola(output);
    
    
    if (!text_sekcija.empty())
        print_text_sekcija(output);
    if (!text_rel.empty())
        print_text_rel_sekcija(output);
    if (!data_sekcija.empty())
        print_data_sekcija(output);
    if (!data_rel.empty())
        print_data_rel_sekcija(output);
    if (!rodata_sekcija.empty())
        print_rodata_sekcija(output);
    
}

string Asembler::int_to_bin(int n){ 
    std::string r;
    while(n!=0) {r=(n%2==0 ?"0":"1")+r; n/=2;}
    return r;
       
}
string Asembler::bin_to_hex(string bin){
    string tmp;
    string binToHex;
    for (size_t j = 0; j < bin.size(); j += 4){
        tmp = bin.substr(j, 4);
        if      (!tmp.compare("0000")) binToHex += "0";
        else if (!tmp.compare("0001")) binToHex += "1";
        else if (!tmp.compare("0010")) binToHex += "2";
        else if (!tmp.compare("0011")) binToHex += "3";
        else if (!tmp.compare("0100")) binToHex += "4";
        else if (!tmp.compare("0101")) binToHex += "5";
        else if (!tmp.compare("0110")) binToHex += "6";
        else if (!tmp.compare("0111")) binToHex += "7";
        else if (!tmp.compare("1000")) binToHex += "8";
        else if (!tmp.compare("1001")) binToHex += "9";
        else if (!tmp.compare("1010")) binToHex += "A";
        else if (!tmp.compare("1011")) binToHex += "B";
        else if (!tmp.compare("1100")) binToHex += "C";
        else if (!tmp.compare("1101")) binToHex += "D";
        else if (!tmp.compare("1110")) binToHex += "E";
        else if (!tmp.compare("1111")) binToHex += "F";
        else continue;
    }
    return binToHex;
}
string Asembler::little_endian(string s){

    string h = s.substr(0,8);
    string l = s.substr(8,8);
    return ""+l+h;
}

