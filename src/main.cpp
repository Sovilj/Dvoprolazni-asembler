#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>


#include "asembler.cpp"

using namespace std;

int main(int argc, char ** argv){

    cout << "Welcome"<<endl;

    int start_addr;

    if (argc < 3){
        cout << "Nema argumenata programa, Molimo unesite #inputfile #outputfile" << endl;
        return 1;
    }
    if ( argv[3] == nullptr){
        start_addr = 0;

    }else{
        start_addr = stoi(argv[3]);
    }


    ifstream inputFile(argv[1]);
    ofstream outputFile(argv[2]);


    if(!inputFile.is_open()){
        cout<< "Greska pri otvaranju ulaznog fajla"<<endl;
        return 1;
    }
    if(!outputFile.is_open()){
        cout<< "Greska pri otvaranju izlaznog fajla"<<endl;
        return 1;
    }

  /*  string line;
    getline(inputFile,line);
    cout << "linija iz fajla: "<< line << endl;

    outputFile << line;
    */

    Asembler* asem(new Asembler());

    asem->printWelcome();
    asem->initiate(inputFile,outputFile,start_addr);
    
    return 0;
}