#include<Windows.h>
#include <stdio.h>
DWORD LoadFile(const char* fileName, LPVOID* ppfBuffer);//�����ļ�
void showPEheader(const char* fileName);//show PEͷ
void showSection(const char* fileName);//show ��
PIMAGE_NT_HEADERS FileToNtHeader(LPVOID pFileBuffer);//��λNTͷ
LPVOID ImageBufferToFileBuffer(LPVOID pImageBuffer);//��ImageBufferתΪFileBuffer
LPVOID FileBufferToImageBuffer(LPVOID pFileBuffer);//��FileBufferתΪImageBuffer
PIMAGE_SECTION_HEADER LocateSectionBase(LPVOID pFileBuffer);//��λ��һ���ڵĵ�ַ
void SaveFile(LPVOID pFileBuffer, const char* str, DWORD FileSize);//�����ļ�
LPVOID changeimagebuffer(LPVOID imagebuffer);//�հ�������������
LPVOID NEWSetion(LPVOID pImageBuffer);//�����ڲ�����Ӵ���
DWORD FileSizeget(LPVOID pImageBuffer);//�����ļ���С
LPVOID Setiontoone(LPVOID pImageBuffer);//�ϲ���
DWORD RVAtoFOA(DWORD RVA, LPVOID pImageBuffer);//�ڴ��ַת�ļ���ַ
void showEXPORT_DIRECTORY(LPVOID pFileBuffer);//չʾ��������������
void showRELOCATION(LPVOID pFileBuffer);//չʾ�ض��������
void showBOUND_IMPORT_DESCRIPTOR(LPVOID pFileBuffer);//չʾ�󶨵����
LPVOID injectDESCRIPTOR(LPVOID pFileBuffer);//�󶨵����ע��
/*
��������ض�λ��Ǩ�Ʋ���
*/
LPVOID removeDIRECTORY(LPVOID  pFileBuffer);
void showDESCRIPTOR(LPVOID pFileBuffer);//չʾ������

int main()
{
	const char* newFile = "2.exe";
	const char* fileName = "1.exe";
	//const char* fileName = "calc.exe";
	LPVOID pFileBuffer = NULL;
	showPEheader(fileName);
	DWORD FileSize = LoadFile(fileName, &pFileBuffer);
	LPVOID pImageBuffer = FileBufferToImageBuffer(pFileBuffer);
	//DWORD RVA = 0x1e01, FOA = 0;
	//FOA = RVAtoFOA(RVA, pImageBuffer);
	//printf("%x(RVA) - > %x(FOA)", RVA, FOA);

	//LPVOID pNewFileBuffer= ImageBufferToFileBuffer(pImageBuffer);

	//�¼ӽڱ����
	//LPVOID newsetion = NEWSetion(pImageBuffer);
	//LPVOID pNewFileBuffer = ImageBufferToFileBuffer(newsetion);
	//�ƶ����������
	//showEXPORT_DIRECTORY(pNewFileBuffer);
	//pNewFileBuffer = removeDIRECTORY(pNewFileBuffer);
	//SaveFile(pNewFileBuffer, newFile, FileSizeget(pNewFileBuffer));
	
	//�ϲ��ڲ���
	//LPVOID pSetiontoone = Setiontoone(pImageBuffer);
	//LPVOID pNewFileBuffer = ImageBufferToFileBuffer(pSetiontoone);
	//SaveFile(pNewFileBuffer, newFile, FileSizeget(pNewFileBuffer));


	// �ض����չʾ
	//showRELOCATION(pFileBuffer);
	//չʾ�����

	showDESCRIPTOR(pFileBuffer);
	//չʾ�󶨵����
	//showBOUND_IMPORT_DESCRIPTOR(pFileBuffer);
	
	//LPVOID changeBuffer = changeimagebuffer(pImageBuffer);

	//LPVOID pNewFileBuffer = ImageBufferToFileBuffer(changeBuffer);
	//�󶨵����Ǩ��
	
	LPVOID newsetion = NEWSetion(pImageBuffer);
	LPVOID pNewFileBuffer = ImageBufferToFileBuffer(newsetion);
	pNewFileBuffer = injectDESCRIPTOR(pNewFileBuffer);

	SaveFile(pNewFileBuffer, newFile, FileSizeget(pNewFileBuffer));
	
	//SaveFile(pImageBuffer, newFile,FileSize);
	free(pFileBuffer);
	//free(pImageBuffer);
	//free(newsetion);
	//free(pSetiontoone);
	//free(pNewFileBuffer);
	printf("end\n");






	return 0;

}