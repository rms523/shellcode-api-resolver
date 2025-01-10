global _get_kernel32_address
global _fetch_getprocaddress

section .text

_get_kernel32_address:
  xor eax, eax
  mov eax, [fs:0x30]   ; PEB
  
  mov eax, [eax + 0xC]  ; LDR offset
  
  mov eax, [eax + 0xC]  ; InLoadOrderModuleList
  
  mov eax, [eax] ; ntdll
  
  mov eax, [eax]  ; kernel32
  
  mov eax, [eax + 0x18] ; DLLBase
    
  ret
  
  
_fetch_getprocaddress:

  push 0x00007373   ; ss
  push 0x65726464   ; erdd
  push 0x41636F72   ; Acor
  push 0x50746547   ; PteG
  
  sub esp, 8      ; for local variables
  
  mov eax, [esp + 0x20] ; kernel32_address
  
  mov ebx, [eax + 0x3C] ; e_elfnew 
  
  add ebx, eax          ; Nt header 'PE'
  
  add ebx, 0x78           ; Export directory offset 
  
  mov ebx, [ebx]        ; Export directory rva 
  
  add ebx, eax          ; Export directory VA
  
  add ebx, 0x18         ; Number of names offset 
  
  mov ecx, [ebx]        ; Number of names 
  
  add ebx, 0x4          ; Address of Functions offset 
  
  mov [esp + 0x4], ebx  ; local var, offset of address of functions 
  
  add ebx, 0x4          ; Address of names offset 
  
  mov ebx, [ebx]         ; Address of names rva 
  
  add ebx, eax           ; Address of Names VA 
  
  mov edx, ecx           ; Number of names 
  
  xor ecx, ecx           ; using as index
  
  mov ecx, -1
  
  sub ebx, 4
  
  loop_start:
    
	inc ecx 
	
	cmp ecx, edx
	
	jz loop_end 
	
	
	add ebx, 4           ; dword holding address of function
		
	mov esi, eax         
	
	add esi, [ebx]       ; VA of function name string start
	
	mov edi, [esi]       
	
	cmp edi, [esp+0x8]   ; compare GetP
	
	jnz loop_start
	
	mov edi, [esi + 0x4]
	cmp edi, [esp + 0xC]  ; compare roca
	
	jnz loop_start
	
	mov edi, [esi + 0x8]
	cmp edi,  [esp + 0x10]  ; ddre
	
	jnz loop_start 
	
	movsx edi, word [esi + 0xC]
	movsx esi, word [esp + 0x14]
	
	cmp esi, edi 
	
	jnz loop_start 
	 
	
  loop_end:
  
    cmp ecx, edx         
	jz end_program       ; terminating due to unmatched function name
  	
	mov ebx, [esp + 0x4] ; local var, offset of address of functions 
	
	add ebx, 0x8         ; offset of address of ordinals
	
	mov ebx, [ebx]       ; rva of address of ordinals 
	
	add ebx, eax         ; VA of address of ordinals 
	
	shl ecx, 1           
	
	add ebx, ecx         ; get the matched dword index     
	
	shr ecx, 1            ; restore ecx 
	
	movsx ebx, word [ebx]        ; get the index to address of functions 
	
	mov [esp], ebx        ; store the address of function index as local var 
	
	
	mov ebx, [esp + 0x4]   ; local var, offset of address of functions 
	
	mov ebx, [ebx]        ; rva of address of functions 
	
	add ebx, eax          ; VA of address of functions
	
	
	mov ecx, [esp]
	
	shl ecx, 2            
	
	add ebx, ecx           ; get the appropriate index of function 
	
	add eax , [ebx]        ; get the VA address of getprocaddress 
	
	add esp, 0x18
	
	ret 
	
	
   end_program:
	
	 add esp, 0x18
     xor eax, eax 
	 ret 