#include<Windows.h>
#include <stdio.h>
DWORD LoadFile(const char* fileName, LPVOID* ppfBuffer);//加载文件
void showPEheader(const char* fileName);//show PE头
void showSection(const char* fileName);//show 节
PIMAGE_NT_HEADERS FileToNtHeader(LPVOID pFileBuffer);//定位NT头
LPVOID ImageBufferToFileBuffer(LPVOID pImageBuffer);//从ImageBuffer转为FileBuffer
LPVOID FileBufferToImageBuffer(LPVOID pFileBuffer);//从FileBuffer转为ImageBuffer
PIMAGE_SECTION_HEADER LocateSectionBase(LPVOID pFileBuffer);//定位第一个节的地址
void SaveFile(LPVOID pFileBuffer, const char* str, DWORD FileSize);//保存文件
LPVOID changeimagebuffer(LPVOID imagebuffer);//空白区添加任意代码
LPVOID NEWSetion(LPVOID pImageBuffer);//新增节并且添加代码
DWORD FileSizeget(LPVOID pImageBuffer);//返回文件大小
LPVOID Setiontoone(LPVOID pImageBuffer);//合并节
DWORD RVAtoFOA(DWORD RVA, LPVOID pImageBuffer);//内存地址转文件地址
void showEXPORT_DIRECTORY(LPVOID pFileBuffer);//展示函数导出表内容
void showRELOCATION(LPVOID pFileBuffer);//展示重定向表内容
void showBOUND_IMPORT_DESCRIPTOR(LPVOID pFileBuffer);//展示绑定导入表
LPVOID injectDESCRIPTOR(LPVOID pFileBuffer);//绑定导入表注入
/*
导出表和重定位表迁移测试
*/
LPVOID removeDIRECTORY(LPVOID  pFileBuffer);
void showDESCRIPTOR(LPVOID pFileBuffer);//展示导出表

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

	//新加节表测试
	//LPVOID newsetion = NEWSetion(pImageBuffer);
	//LPVOID pNewFileBuffer = ImageBufferToFileBuffer(newsetion);
	//移动导出表测试
	//showEXPORT_DIRECTORY(pNewFileBuffer);
	//pNewFileBuffer = removeDIRECTORY(pNewFileBuffer);
	//SaveFile(pNewFileBuffer, newFile, FileSizeget(pNewFileBuffer));
	
	//合并节测试
	//LPVOID pSetiontoone = Setiontoone(pImageBuffer);
	//LPVOID pNewFileBuffer = ImageBufferToFileBuffer(pSetiontoone);
	//SaveFile(pNewFileBuffer, newFile, FileSizeget(pNewFileBuffer));


	// 重定向表展示
	//showRELOCATION(pFileBuffer);
	//展示导入表

	showDESCRIPTOR(pFileBuffer);
	//展示绑定导入表
	//showBOUND_IMPORT_DESCRIPTOR(pFileBuffer);
	
	//LPVOID changeBuffer = changeimagebuffer(pImageBuffer);

	//LPVOID pNewFileBuffer = ImageBufferToFileBuffer(changeBuffer);
	//绑定导入表迁移
	
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