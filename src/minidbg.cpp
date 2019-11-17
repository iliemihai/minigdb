#include <vector>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sstream>
#include <iostream>
#include "debugger.h"
#include "breakpoint.h"
#include "linenoise.h"

using namespace minidbg;

//helper functions
std::vector<std::string> split(const std::string& s, char delimiter){
    std::vector<std::string> out{};
    std::stringstream ss{s};
    std::string item;

    while(std::getline(ss, item, delimiter)){
        out.push_back(item);
    }
    return out;
}

bool is_prefix(const std::string& s, const std::string& of) {
    if(s.size() > of.size())
        return false;
    return std::equal(s.begin(), s.end(), of.begin());
}

void debugger::run(){
    int wait_status;
    auto options = 0;
    waitpid(m_pid, &wait_status, options);

    char* line = nullptr;
    while((line = linenoise("minidbg> "))!=nullptr){
	//after we knwo the process is ready to be debugged, we listen
	//for user input. we give the command th hanndle_input, after we add
	//the command to linenoise history and free the resource
    handle_command(line);
	linenoiseHistoryAdd(line);
	linenoiseFree(line);
    }
}

void debugger::continue_execution(){
    ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);

    int wait_status;
    auto options = 0;
    waitpid(m_pid, &wait_status, options);
}

void debugger::handle_command(const std::string& line){
    auto args = split(line, ' ');
    auto command = args[0];
    //will follow the similar format of gdb
    if(is_prefix(command, "continue")){
        continue_execution();
    }
    else if (is_prefix(command, "break")){
        std::string addr{args[1], 2};//naively assume user has writen ad 0xADDRESS
        set_breakpoint_at_address(std::stol(addr, 0, 16));
    }
    else{
        std::cerr<<"Unknown command\n";
    }
}

//real magic happens in enable and disable

void breakpoint::enable(){
    //need to replace the instruction wich is currently at the given
    //address with int 3 instruction, encoded as 0xcc.
    //we also want to save what is at that address so we can restore the code later

    //PTRACE_PEEK request to ptrace how to read the memory of the traced process, 
    //parameters process id and mem addr and  returns 64 bits that are the curr address
    // data&~0xff zeroes the bottom byte, bitwise OR with int 3 set the breakpoint
    //set the breakpoint by overwritting memory with PTRACA_POKEDATA
    auto data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, nullptr);
    m_saved_data = static_cast<uint8_t>(data & 0xff);//save bottom byte
    uint64_t int3 = 0xcc;
    uint64_t data_with_int3 = ((data & ~0xff) | int3); //set bottom byte to 0xcc
    ptrace(PTRACE_POKEDATA, m_pid, m_addr, data_with_int3);

    m_enabled = true;
}

void breakpoint::disable(){
    //ptrace request operate on whole word-> read word at the location to restore
    //overwrite the low byte with original, and write back to memory
    auto data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, nullptr);
    auto restored_data = ((data & ~0xff) | m_saved_data);
    ptrace(PTRACE_POKEDATA, m_pid, m_addr, restored_data);

    m_enabled = false;
}

void debugger::set_breakpoint_at_address(std::intptr_t addr) {
    std::cout << "Set breakpoint at address 0x" << std::hex << addr << std::endl;
    breakpoint bp{m_pid, addr};
    bp.enable();
    m_breakpoints[addr] = bp;
}

int main(int argc, char** argv){
    if(argc<2) {
        std::cerr<<"Program name not specified";
	return -1;
    }

    auto prog = argv[1];

    //we call for because we want program to split in two processes
    //in the child process fork return 0
    //in the parrent process fork return ID of child process
    auto pid = fork();
    if(pid == 0){
        //we are in the child process
	//replace whatever we are doing with programm
	//we want to debug
	
	//ptrace allows us to observe and co0ntrol execution of
	//another process by reading registers, memory, single stepping,more
	//API is ugly:single function which you provide with an enumerator value+ arguments which will be used or ignored depending on which value you suply
	//signature long ptrace(enum __ptrace_request request, pid_t pid,
        //    void *addr, void *data);
	//    request = what we would like to do to trced process
	//    pid is the process id of traced process
	//    addr is memory address; designate address in the tracee
	//    datarequest specific resource.
	//    PTRACE_TRACEME indicates that this process should 
	//    allow its parrent to trace it.
	//
	//    when traced process is launched it will be sent a 
	//    SIGTRAP signal, which is a trace or breakpoint or trap.
	//    we can wait untill signal id sent using waipid func
	ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
	//execl execute the given program, passing the name of it 
	//as a command-line argument and a nullptr to terminate the list
	execl(prog, prog, nullptr);
    }else if (pid>=1){
        //we are in the parrent process
	//execute debugger/
	debugger dbg{prog, pid};
	dbg.run();
    }
}
