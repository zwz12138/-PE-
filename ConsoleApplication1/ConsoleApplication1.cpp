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
DWORD RVAtoFOA(DWORD RVA, LPVOID pImageBuffer);//内存地址转文件地址
void showEXPORT_DIRECTORY(LPVOID pFileBuffer);//展示函数导出表内容


//#define MESSAGE_BOX_ADDRESS (DWORD)0x7DCBFD1E
#define MESSAGE_BOX_ADDRESS (DWORD)&MessageBox
//shellcode定义
BYTE shellcode[] = {
	0x6A,00,0x6A,00,0x6A,00,0x6A,00,
	0xE8,00,00,00,00,
	0xE9,00,00,00,00,
};

/*
* 函数功能：加载文件
* 参数说明：filename：文件名
* 返回值：通过malloc分配的内存的大小，若无法分配则返回0
* 使用该函数后需要调用free（）函数释放堆空间
*/
DWORD LoadFile(const char* fileName, LPVOID* ppfBuffer)
{
	FILE* fp;
	DWORD FileSize = 0;
	fopen_s(&fp, fileName, "rb");
	if (fp == NULL)
	{
		printf("cannot open %s", fileName);
		exit(EXIT_FAILURE);
	}
	fseek(fp, 0, SEEK_END);
	FileSize = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	*ppfBuffer = (LPVOID*)malloc(FileSize);
	if (*ppfBuffer == NULL)
	{
		printf("cannot malloc");
		return 0;
	}

	memset(*ppfBuffer, 0, FileSize);
	fread(*ppfBuffer, FileSize, 1, fp);
	if (fclose(fp) != 0)
	{
		printf("cannot close file");
		exit(EXIT_FAILURE);
	}
	return FileSize;

	/*
	* 函数功能：打印PE头信息
	* 参数说明：filename：文件名
	* 返回值：无
	*
	*/
}
void showPEheader(const char* fileName)
{
	LPVOID pFileBuffer = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	LoadFile(fileName, &pFileBuffer);
	if (pFileBuffer == NULL)
	{
		printf("cannot open file");
		exit(EXIT_FAILURE);
	}
	//判断是否为MZ
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("不是有效的MZ标志");
		free(pFileBuffer);
		return;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	printf("***********DOS Header**********\n");
	printf("pDosHeader->e_magic	MZ 标志:%x\n", pDosHeader->e_magic);
	printf("pDosHeader->e_lfanew	PE 偏移:%x\n", pDosHeader->e_lfanew);
	//判断PE偏移是否有效
	//* (PDWORD) ptr1 = *(PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	if (*(PDWORD)((ULONG_PTR)pFileBuffer + (pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("不是有效的PE标志");
		free(pFileBuffer);
		return;
	}
	pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pFileBuffer + pDosHeader->e_lfanew);
	printf("*********NT Header**************\n");
	printf("pNtHeaders->Signature	PE 标志 :%x\n", pNtHeaders->Signature);
	puts("*********PE Header**************");
	printf("FileHeader.Machine		CPU平台:%x\n", pNtHeaders->FileHeader.Machine);
	printf("pNtHeaders->FileHeader.NumberOfSections	PE文件中区块数量:%x\n", pNtHeaders->FileHeader.NumberOfSections);
	printf("pNtHeaders->FileHeader.Characteristics		(描述文件属性）:%x\n", pNtHeaders->FileHeader.Characteristics);
	puts("*********Optional PE Header**************");
	printf("pNtHeaders->OptionalHeader.Magic	可选PE头幻数：%x\n", pNtHeaders->OptionalHeader.Magic);
	printf("pNtHeaders->OptionalHeader.AddressOfEntryPoint		:OEP程序入口点 %x\n", pNtHeaders->OptionalHeader.AddressOfEntryPoint);
	printf("ImageBase      	:%x\n", pNtHeaders->OptionalHeader.ImageBase);






	free(pFileBuffer);

	return;
}
/*
	* 函数功能：打印所有节信息
	* 参数说明：filename：文件名
	* 返回值：无
	*
	*/
void showSection(const char* fileName)
{
	LPVOID pFileBuffer = NULL;
	LoadFile(fileName, &pFileBuffer);
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	if (pFileBuffer == NULL)
	{
		printf("cannot load file");
		return;
	}

	PIMAGE_NT_HEADERS pNtHeader = NULL;
	PIMAGE_DOS_HEADER pDosHeader = NULL;

	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pNtHeader = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + (BYTE*)pFileBuffer);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("不是标准的PE文件");
		return;
	}

	printf("*******Section *********\n");
	WORD sectionNum = pNtHeader->FileHeader.NumberOfSections;
	LPVOID base = (LPVOID)(pDosHeader->e_lfanew + sizeof(DWORD) + (BYTE*)pFileBuffer + sizeof(_IMAGE_FILE_HEADER)\
		+ pNtHeader->FileHeader.SizeOfOptionalHeader);

	for (size_t i = 0; i < sectionNum; i++)
	{
		LPVOID nowSection = (LPVOID)((BYTE*)base + i * sizeof(_IMAGE_SECTION_HEADER));
		pSectionHeader = (PIMAGE_SECTION_HEADER)nowSection;
		printf("*******Section %u*********\n", i);

		printf("name:");
		for (size_t i = 0; i < 8; i++)
		{
			printf("%c", pSectionHeader->Name[i]);
		}
		printf("\n");
		printf("VirtualAddress:%x\n", pSectionHeader->VirtualAddress);
		printf("PointerToRawData:%x\n", pSectionHeader->PointerToRawData);
		printf("MISC:%x\n", pSectionHeader->Misc.VirtualSize);
		printf("SizeOfRawData:%x\n", pSectionHeader->SizeOfRawData);

	}
	free(pFileBuffer);
	printf("END SECTION");
	return;
}
/*
	* 函数功能：寻找DOS头
	* 参数说明：pFileBuffer：文件缓冲指针
	* 返回值：DOS头指针
	*注意：无
	*/
PIMAGE_DOS_HEADER FileToDosHeader(LPVOID pFileBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	if (pFileBuffer == NULL)
	{
		printf("不接受NULL");
		return NULL;
	}
	//检测MZ头
	if (*((WORD*)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("不是标准MZ头！");
		return NULL;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	return pDosHeader;
}



/*
函数功能：接受文件缓冲区指针，返回NT头指针
参数：文件缓冲区指针
返回值：如果鉴别出符合标准PE文件，返回NT头，否则返回NULL
注意：无
*/
PIMAGE_NT_HEADERS FileToNtHeader(LPVOID pFileBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	if (pFileBuffer == NULL)
	{
		printf("FileToNtHeader函数不接受NULL");
		return NULL;
	}
	//检测MZ头
	if (*((WORD*)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("不是标准MZ头！");
		return NULL;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	//检测PE签名
	if (*(DWORD*)(pDosHeader->e_lfanew + (BYTE*)pFileBuffer) != IMAGE_NT_SIGNATURE)
	{
		printf("不是标准NT头！");
		return NULL;
	}
	pNtHeaders = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + (BYTE*)pFileBuffer);
	return pNtHeaders;
}
/*
函数功能：接受文件缓冲区指针，返回第一个节表的地址
参数：文件缓冲区指针
返回值：如果鉴别出符合标准PE文件，返回第一个节表的地址，否则返回NULL
注意：无
*/
PIMAGE_SECTION_HEADER LocateSectionBase(LPVOID pFileBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	PIMAGE_SECTION_HEADER pSectionHeaderBase = NULL;
	if (pFileBuffer == NULL)
	{
		printf("不接受NULL");
		return NULL;
	}
	//检测MZ头
	if (*((WORD*)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("不是标准MZ头！");
		return NULL;
	}
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	//检测PE签名
	if (*(DWORD*)(pDosHeader->e_lfanew + (BYTE*)pFileBuffer) != IMAGE_NT_SIGNATURE)
	{
		printf("不是标准NT头！");
		return NULL;
	}
	pNtHeaders = (PIMAGE_NT_HEADERS)(pDosHeader->e_lfanew + (BYTE*)pFileBuffer);
	/*
	pSectionHeaderBase = (PIMAGE_SECTION_HEADER)((BYTE*)pFileBuffer + pDosHeader->e_lfanew + sizeof(DWORD)\
		+ sizeof(IMAGE_FILE_HEADER) + pNtHeaders->FileHeader.SizeOfOptionalHeader); //第一个节表指针地址=文件地址+dos头的e_lfnew偏移+PE标志位+PE头大小+可选头大小（NT头的SizeOfOptionalHeader
	*/
	pSectionHeaderBase = (PIMAGE_SECTION_HEADER)((DWORD)pFileBuffer + pDosHeader->e_lfanew + sizeof(DWORD)\
		+ sizeof(IMAGE_FILE_HEADER) + pNtHeaders->FileHeader.SizeOfOptionalHeader); //第一个节表指针地址=文件地址+dos头的e_lfnew偏移+PE标志位+PE头大小+可选头大小（NT头的SizeOfOptionalHeader
	return pSectionHeaderBase;
}





/*
 函数功能：FileBufferToImageBuffer
参数说明：pFileBuffer：文件缓冲指针
返回值：内存映像指针
注意：用完记得free（）哦
*/
LPVOID FileBufferToImageBuffer(LPVOID pFileBuffer)
{
	DWORD SizeOfImage = 0;
	DWORD SizeOfHeaders = 0;
	WORD NumberOfSections = 0;
	PIMAGE_SECTION_HEADER pSectionHeaderBase = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	LPVOID pImageBuffer = NULL;

	if (pFileBuffer == NULL)
	{
		printf("cannot transform NULL\n");
		return NULL;
	}
	pNtHeaders = FileToNtHeader(pFileBuffer);
	if (pNtHeaders == NULL)
	{
		printf("NT头为空！\n");
		return NULL;
	}
	SizeOfImage = pNtHeaders->OptionalHeader.SizeOfImage;  //获取占用内存大小
	SizeOfHeaders = pNtHeaders->OptionalHeader.SizeOfHeaders;  //获取头大小
	NumberOfSections = pNtHeaders->FileHeader.NumberOfSections; //获取节大小
	pSectionHeaderBase = LocateSectionBase(pFileBuffer); //获取第一个节表位置 
														 //第一个节表地址=文件地址+dos头的e_lfnew偏移+PE标志位+PE头大小+可选头大小（NT头的SizeOfOptionalHeader

	pImageBuffer = malloc(SizeOfImage);
	if (pImageBuffer == NULL)
	{
		printf("cannot malloc memory");
		return NULL;
	}

	memset(pImageBuffer, 0, SizeOfImage);
	memcpy(pImageBuffer, pFileBuffer, SizeOfHeaders);//先把文件头放在内存中

	for (size_t i = 0; i < NumberOfSections; i++)
	{
		PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)\
			((BYTE*)pSectionHeaderBase + sizeof(IMAGE_SECTION_HEADER) * i);//节表大小*第几个节表
		memcpy((BYTE*)pImageBuffer + pSectionHeader->VirtualAddress,
			(BYTE*)pFileBuffer + pSectionHeader->PointerToRawData,
			pSectionHeader->SizeOfRawData);
	}
	return pImageBuffer;
}
bool textbycmp(BYTE a[], BYTE b[], int i)
{
	int x = 0;
	for (int x = 0; x < i; x++)
	{
		if (a[x] != b[x])
		{
			return false;
		}
		x++;
	}
	return true;
}
/*
函数功能：ImageBufferToFileBuffer
参数说明：pImageBuffer：内存映像指针
返回值：pFileBuffer
注意：记得free（）哦
*/
LPVOID ImageBufferToFileBuffer(LPVOID pImageBuffer)
{
	PIMAGE_NT_HEADERS pNtHeaders = FileToNtHeader(pImageBuffer);
	DWORD FileSize = 0;
	PIMAGE_SECTION_HEADER SectionBase = NULL;
	DWORD NumberOfSections = 0;
	if (pNtHeaders == NULL)
	{
		printf("error");
		exit(0);
	}
	SectionBase = LocateSectionBase(pImageBuffer);//计算的第一个节表的大小
	NumberOfSections = pNtHeaders->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pLastSection = (PIMAGE_SECTION_HEADER)\
		((BYTE*)SectionBase + (NumberOfSections - 1) * sizeof(IMAGE_SECTION_HEADER));
	FileSize = pLastSection->SizeOfRawData + pLastSection->PointerToRawData;  //获取文件大小=最后一个节的大小（节在文件中大小）+文件偏移（pointertorawdata）
	LPVOID pFileBuffer = malloc(FileSize);
	if (pFileBuffer == NULL)
	{
		printf("cannot malloc");
		return NULL;
	}
	memset(pFileBuffer, 0, FileSize);
	memcpy(pFileBuffer, pImageBuffer, pNtHeaders->OptionalHeader.SizeOfHeaders);//拷贝pe文件头


	BYTE bsste[] = {
		0x2E,0x74,0x65,0x78,0x74,0x62,0x73,0x73
	};
	for (size_t i = 0; i < NumberOfSections; i++)
	{
		PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)\
			((BYTE*)SectionBase + i * sizeof(IMAGE_SECTION_HEADER));
		BYTE sectionhe[8] = {};
		memcpy(sectionhe, pSectionHeader->Name, sizeof(pSectionHeader->Name));//跳过textbss节
		//sectionhe = (pSectionHeader->Name);
		if (!textbycmp(sectionhe, bsste, 8)) {
			memcpy((BYTE*)pFileBuffer + pSectionHeader->PointerToRawData,
				(BYTE*)pImageBuffer + pSectionHeader->VirtualAddress,
				pSectionHeader->SizeOfRawData);//从内存偏移的地方拷贝文件对齐的大小到原来文件中的节的位置
		}

	}


	return pFileBuffer;

}
/*
函数功能：返回文件大小
参数：文件缓冲指针，将保存文件的绝对地址，文件大小
返回值：无
注意：无
*/
DWORD FileSizeget(LPVOID pImageBuffer) {
	PIMAGE_NT_HEADERS pNtHeaders = FileToNtHeader(pImageBuffer);
	DWORD FileSize = 0;
	PIMAGE_SECTION_HEADER SectionBase = NULL;
	DWORD NumberOfSections = 0;
	if (pNtHeaders == NULL)
	{
		printf("error");
		exit(0);
	}
	SectionBase = LocateSectionBase(pImageBuffer);//计算的第一个节表的大小
	NumberOfSections = pNtHeaders->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pLastSection = (PIMAGE_SECTION_HEADER)\
		((BYTE*)SectionBase + (NumberOfSections - 1) * sizeof(IMAGE_SECTION_HEADER));
	FileSize = pLastSection->SizeOfRawData + pLastSection->PointerToRawData;  //获取文件大小=最后一个节的大小（节在文件中大小）+文件偏移（pointertorawdata）

	return FileSize;

}
/*
函数功能：从pFilBuffer指向的地址开始，FileSize大小的数据保存于str指定的绝对地址中
参数：文件缓冲指针，将保存文件的绝对地址，文件大小
返回值：无
注意：无
*/
void SaveFile(LPVOID pFileBuffer, const char* str, DWORD FileSize)
{
	FILE* fp;
	fopen_s(&fp, str, "wb");
	if (fp == NULL)
	{
		printf("cannot open %s", str);
		return;
	}
	fwrite(pFileBuffer, FileSize, 1, fp);
	if (fclose(fp) != 0)
	{
		printf("cannot close %s", str);
		return;
	}
	return;
}
/*
功能：任意文件写入shellcode
接受imagebuffer
返回修改后的imagebuffer
*/
LPVOID changeimagebuffer(LPVOID imagebuffer) {
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	DWORD SizeOfImage = 0;
	DWORD SizeOfHeaders = 0;
	WORD NumberOfSections = 0;
	PIMAGE_SECTION_HEADER pSectionHeaderBase = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	LPVOID pImageBuffer = NULL;
	PBYTE codebegin = NULL;



	pDosHeader = (PIMAGE_DOS_HEADER)imagebuffer;
	pNtHeaders = FileToNtHeader(imagebuffer);

	//判断空闲区是否能存储shellcode代码(文件对齐大小-misc里真实内存大小）
	pSectionHeaderBase = (PIMAGE_SECTION_HEADER)((DWORD)LocateSectionBase(imagebuffer));
	pSectionHeaderBase = (PIMAGE_SECTION_HEADER)((DWORD)pSectionHeaderBase + 0x28);//这里写第二个节表是为了测试vs编译的程序嫩否注入（因为第一个节是textbss段）
	if (((pSectionHeaderBase->SizeOfRawData) - (pSectionHeaderBase->Misc.VirtualSize)) < sizeof(shellcode))
	{
		printf("代码空闲区不足");
		free(imagebuffer);
		return NULL;
	}

	//把代码复制到空闲区
	codebegin = (PBYTE)((DWORD)imagebuffer + pSectionHeaderBase->VirtualAddress + pSectionHeaderBase->Misc.VirtualSize);
	memcpy(codebegin, shellcode, sizeof(shellcode));
	//修正E8

	DWORD e8addr = (DWORD)(MESSAGE_BOX_ADDRESS - (pNtHeaders->OptionalHeader.ImageBase + ((DWORD)codebegin + (DWORD)0x0D - (DWORD)imagebuffer)));
	//e8addr = 0x7D8A55E1;
	*(PDWORD)(codebegin + 9) = e8addr;
	// 修正E9
	DWORD e9addr = (DWORD)((pNtHeaders->OptionalHeader.ImageBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint) - (pNtHeaders->OptionalHeader.ImageBase + ((DWORD)codebegin + (DWORD)0x12 - (DWORD)imagebuffer)));
	//e9addr = 0xFFFFDC95;
	*(PDWORD)(codebegin + 0xE) = e9addr;
	//pSectionHeaderBase = (PIMAGE_SECTION_HEADER)(BYTE*)imagebuffer + pDosHeader->e_lfanew + sizeof(IMAGE_); 

	pNtHeaders->OptionalHeader.AddressOfEntryPoint = (DWORD)codebegin - (DWORD)imagebuffer;
	//pNtHeaders->OptionalHeader.AddressOfEntryPoint = 0x01A730;
	return imagebuffer;


}
/*
函数功能：新增节
参数：内存映像指针
返回值：内存映像指针
注意：无
*/
LPVOID NEWSetion(LPVOID pImageBuffer) {
	/*
1)添加一个新的节(可以copy一份)
2)在新增节后面填充一个节大小的000
3)修改PE头中节的数量
4)修改sizeofimage的大小
5)再原有数据的最后，新增一个节的数据(内存对齐的整数倍).
6)修正新增节表的属性

注意：SizeOfHeader - (DOS +垃圾数据+ PE标记+标准PE头+可选PE头+己存在节表)= 2个节表的大小

空间不够可以把PE头往上移动（占DOS头的垃圾数据）
	
	*/
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	DWORD SizeOfImage = 0;
	DWORD SizeOfHeaders = 0;
	WORD NumberOfSections = 0;
	DWORD pointtonew = 0;
	PIMAGE_SECTION_HEADER pSectionHeaderBase = NULL;
	PIMAGE_SECTION_HEADER pnewSectionHeaderBase = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	//LPVOID pImageBuffer = NULL;
	PBYTE codebegin = NULL;

	pNtHeaders = FileToNtHeader(pImageBuffer);//nt头
	//内存对齐大小
	const DWORD size = pNtHeaders->OptionalHeader.SectionAlignment;

	LPVOID npFileBuffer = malloc(pNtHeaders->OptionalHeader.SizeOfImage + size);


	memset(npFileBuffer,0x00 , pNtHeaders->OptionalHeader.SizeOfImage + size);
	memcpy(npFileBuffer, pImageBuffer, pNtHeaders->OptionalHeader.SizeOfImage);

	pImageBuffer = npFileBuffer;
	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;//dos头
	pNtHeaders = FileToNtHeader(pImageBuffer);//nt头
	
	//验证剩余空间是否够2个节表大小
	DWORD freesp = pNtHeaders->OptionalHeader.SizeOfHeaders - (pDosHeader->e_lfanew + 0x4 + 0x14 + pNtHeaders->FileHeader.SizeOfOptionalHeader + (pNtHeaders->FileHeader.NumberOfSections * 0x28));
	if (freesp < 0x28 * 2)
	{
		printf ("空间不足够添加节表，添加失败");
		return pImageBuffer;
	};


	//找最后一个节表结束的位置添加节
	pSectionHeaderBase = LocateSectionBase(pImageBuffer);
	LPVOID addsectionstart = (BYTE*)pSectionHeaderBase + (DWORD)(0x28 * (pNtHeaders->FileHeader.NumberOfSections));
	memcpy(addsectionstart, (BYTE*)pSectionHeaderBase+0x28, 0x28);

	//在内存最后添加一个内存对齐整数倍的00
	LPVOID endexe = (BYTE*)pImageBuffer + pNtHeaders->OptionalHeader.SizeOfImage ;


	BYTE* tian1 = new BYTE[size];
	memset(tian1, 0x00,  size);

	//tian1  
	//BYTE tian[4096] = { 0x00 };
	memcpy(endexe, tian1 , size);

	//修改sizeofimage大小
	pNtHeaders->OptionalHeader.SizeOfImage = pNtHeaders->OptionalHeader.SizeOfImage + size;

	//修改新添加节的属性
	pnewSectionHeaderBase =(PIMAGE_SECTION_HEADER) addsectionstart;
	pnewSectionHeaderBase->Misc.VirtualSize = size;
	pnewSectionHeaderBase->VirtualAddress = (DWORD) endexe - (DWORD) pImageBuffer;
	pnewSectionHeaderBase->SizeOfRawData = size;
	//文件中偏移,先找上一个节的文件偏移+是一个节的大小（偷懒直接看是不是SizeOfRawData打过真实大小，直接加了）
	PIMAGE_SECTION_HEADER presec = PIMAGE_SECTION_HEADER((BYTE*)pnewSectionHeaderBase - 0x28);
	if (presec->SizeOfRawData > presec->Misc.VirtualSize)
	{
		pointtonew = presec->SizeOfRawData + presec->PointerToRawData;
	}
	else
	{
		return 0;
	}
	pnewSectionHeaderBase->PointerToRawData = pointtonew;



	//+pNtHeaders->OptionalHeader.SectionAlignment
	//修改节的数量+1
	pNtHeaders->FileHeader.NumberOfSections = pNtHeaders->FileHeader.NumberOfSections + 1;



	return pImageBuffer;
}

/*
函数功能：合并节
参数：内存映像指针
返回值：内存映像指针
注意：无
1、拉伸到内存
2、将第一个节的内存大小、文件大小改成一样
	   Max = SizeOfRawData>VirtualSize?SizeOfRawData:VirtualSize
   SizeOfRawData = VirtualSize = 最后一个节的VirtualAddress + Max - SizeOfHeaders内存对齐后的大小
3、将第一个节的属性改为包含所有节的属性
4、修改节的数量为1
*/
LPVOID Setiontoone(LPVOID pImageBuffer) {
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	DWORD SizeOfImage = 0;
	DWORD SizeOfHeaders = 0;
	DWORD SizeOfRawData = 0;
	DWORD VirtualSize = 0;
	DWORD MAX = 0;
	WORD NumberOfSections = 0;
	DWORD pointtonew = 0;
	PIMAGE_SECTION_HEADER pSectionHeaderBase = NULL;
	PIMAGE_SECTION_HEADER pnewSectionHeaderBase = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;

	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;//dos头
	pNtHeaders = FileToNtHeader(pImageBuffer);//nt头

	//SizeOfHeaders内存对齐后的大小
	pSectionHeaderBase = LocateSectionBase(pImageBuffer);
	DWORD SizeOfHeadersmem = pSectionHeaderBase->VirtualAddress;
	//找最后一个节
	PIMAGE_SECTION_HEADER pLaswSectionHeaderBase = PIMAGE_SECTION_HEADER ((BYTE*)pSectionHeaderBase + (DWORD)(0x28 * (pNtHeaders->FileHeader.NumberOfSections-1)));
	//Max = SizeOfRawData>VirtualSize?SizeOfRawData:VirtualSize
	if (pLaswSectionHeaderBase->SizeOfRawData > pLaswSectionHeaderBase->Misc.VirtualSize)
	{
		MAX = pLaswSectionHeaderBase->SizeOfRawData;
	}
	else
	{
		MAX = pLaswSectionHeaderBase->Misc.VirtualSize;
	}
	//SizeOfRawData = VirtualSize = 最后一个节的VirtualAddress + Max - SizeOfHeaders内存对齐后的大小
	SizeOfRawData = pLaswSectionHeaderBase->VirtualAddress + MAX - SizeOfHeadersmem;
	/*
	修改节表属性
	*/
	for (int x = 1; x < pNtHeaders->FileHeader.NumberOfSections ; x++) {
		PIMAGE_SECTION_HEADER pSectiontime = (PIMAGE_SECTION_HEADER)((BYTE*)pSectionHeaderBase +x* 0x28);
		pSectionHeaderBase->Characteristics = pSectiontime->Characteristics | pSectionHeaderBase->Characteristics;
	}
	//修改节表数量
	pNtHeaders->FileHeader.NumberOfSections = 1;

	//修改第一个节表属性
	pSectionHeaderBase->SizeOfRawData = SizeOfRawData;
	pSectionHeaderBase->Misc.VirtualSize = SizeOfRawData;

	//修改所有节的属性



	return pImageBuffer;
}

/*
函数功能：转换RVA为FOA，返回之
参数：RVA，内存映像指针
返回值：FOA，转换失败则返回-1
注意：无
*/
DWORD RVAtoFOA(DWORD RVA, LPVOID pImageBuffer)
{
	PIMAGE_NT_HEADERS pNtHeaders = FileToNtHeader(pImageBuffer);
	PIMAGE_SECTION_HEADER SectionBase = LocateSectionBase(pImageBuffer);
	WORD NumberOfSection = 0;

	if (pNtHeaders == NULL || SectionBase == NULL)
	{
		printf("无法找到指针指向的NT头或节表基址");
		return -1;
	}
	if (RVA < pNtHeaders->OptionalHeader.SizeOfHeaders) {
		return RVA;
	}
	NumberOfSection = pNtHeaders->FileHeader.NumberOfSections;
	//循环遍历节表真实地址，如果在2个真实地址之间则计算该地址对节表VirtualAddress的偏移，等于相对文件中pointerToRawData的地址
	for (size_t i = 0; i < NumberOfSection; i++)
	{
		PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)\
			((BYTE*)SectionBase + i * sizeof(IMAGE_SECTION_HEADER));
		PIMAGE_SECTION_HEADER pNextSectionHeader = (PIMAGE_SECTION_HEADER)\
			((BYTE*)SectionBase + (i + 1) * sizeof(IMAGE_SECTION_HEADER));
		if (i == NumberOfSection - 1)
			return RVA - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
		else if (RVA > pSectionHeader->VirtualAddress && RVA < pNextSectionHeader->VirtualAddress)
			return RVA - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
	}
	return 0;
}
/*
展示导出表，需要文件指针
*/
void showEXPORT_DIRECTORY(LPVOID pFileBuffer) {

	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	PIMAGE_EXPORT_DIRECTORY exportDIRECTORY = NULL;

	pNtHeaders = FileToNtHeader(pFileBuffer);
	exportDIRECTORY = (PIMAGE_EXPORT_DIRECTORY) pNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress;
	exportDIRECTORY = (PIMAGE_EXPORT_DIRECTORY) RVAtoFOA((DWORD)exportDIRECTORY, pFileBuffer);
	printf("******************************\n");
	printf("导出表文件地址:%x\n", exportDIRECTORY);

	PIMAGE_EXPORT_DIRECTORY exportDIRECTORYfilebuffer = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)exportDIRECTORY + (DWORD)pFileBuffer);

	printf("导出表函数个数:%x\n", exportDIRECTORYfilebuffer->NumberOfFunctions);
	printf("导出表有名字的函数个数:%x\n", exportDIRECTORYfilebuffer->NumberOfNames);
	printf("******************************\n");
	printf("导出表函数地址表文件地址:%x\n", RVAtoFOA(exportDIRECTORYfilebuffer->AddressOfFunctions,pFileBuffer));

	for (int i = 0; i < exportDIRECTORYfilebuffer->NumberOfFunctions; i++) {

		DWORD* tureAddressOfFunctions = (DWORD*)((DWORD)pFileBuffer + RVAtoFOA(exportDIRECTORYfilebuffer->AddressOfFunctions, pFileBuffer)) + i;
		printf("导出表函数地址表文件地址%x:%x\n", i,(DWORD)RVAtoFOA((DWORD)tureAddressOfFunctions- (DWORD)pFileBuffer,pFileBuffer));
		printf("导出表函数地址表内容-函数地址%x:%x\n", i, *tureAddressOfFunctions);
	}
	printf("******************************\n");
	printf("导出表函数名字表文件地址:%x\n", RVAtoFOA(exportDIRECTORYfilebuffer->AddressOfNames, pFileBuffer));

	for (int i = 0; i < exportDIRECTORYfilebuffer->NumberOfNames; i++) {
	DWORD* tureAddressOfNames = (DWORD*)((DWORD)pFileBuffer + RVAtoFOA(exportDIRECTORYfilebuffer->AddressOfNames, pFileBuffer))+i;
	printf("导出表函数名字表文件中地址的值:%x\n", *tureAddressOfNames);

	printf("导出表函数名字表文件地址:%x\n", RVAtoFOA((DWORD)*tureAddressOfNames,pFileBuffer));

		PCHAR Nameaddr = (PCHAR)((BYTE*)RVAtoFOA((DWORD)*tureAddressOfNames, pFileBuffer) + (DWORD)pFileBuffer);
		printf("导出表函数%x名字:%s\n",i,Nameaddr );
	}
	printf("******************************\n");
	printf("导出表函数序号表base:%x\n", exportDIRECTORYfilebuffer->Base);
	printf("导出表函数序号表文件地址:%x\n", RVAtoFOA(exportDIRECTORYfilebuffer->AddressOfNameOrdinals, pFileBuffer));

	for (int i = 0; i < exportDIRECTORYfilebuffer->NumberOfNames; i++) {
		WORD* tureAddressOfxvhao = (WORD*)((DWORD)pFileBuffer + RVAtoFOA(exportDIRECTORYfilebuffer->AddressOfNameOrdinals, pFileBuffer)) + i;
		printf("导出表函数序号表序号[%x]的值:%x\n", i,*tureAddressOfxvhao);

		///printf("导出表函数名字表文件地址:%x\n", RVAtoFOA((DWORD)*tureAddressOfxvhao, pFileBuffer));

		//PWORD idaddr = (PWORD)((BYTE*)RVAtoFOA((DWORD)*tureAddressOfxvhao, pFileBuffer) + (DWORD)pFileBuffer);
		//printf("导出表函数名字表文件地址:%d\n", idaddr);
	}


}	

/*
展示重定位表块的内容
*/
void showRELOCATIONsetion(DWORD numofsetion,WORD* start,DWORD addrbase, LPVOID pFileBuffer)
{
	for (DWORD i = 0;i < numofsetion;i++)
	{
		WORD time = *start;
		DWORD addradd = (time & 0xFFF)+addrbase;

		if (((time & 0xF000) >> 12) == 3)
		{
			printf("块需要修改，块高4位%x,后12位%x,RVA的值%x,,FOA值%x\n", ((time & 0xF000) >> 12),(time & 0xFFF),addradd,RVAtoFOA(addradd,pFileBuffer));
		}
		else {
			printf("块不需要修改，块高4位%x,后12位%x,RVA的值%x,FOA值%x\n", ((time & 0xF000) >> 12), (time & 0xFFF),addradd, RVAtoFOA(addradd, pFileBuffer));
		}
		

		start = start + 1;
	}
}/*
展示重定位表，需要文件指针
*/

void showRELOCATION(LPVOID pFileBuffer) {
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	PIMAGE_BASE_RELOCATION pRELOCATIONDIRECTORY = NULL;
	PIMAGE_BASE_RELOCATION pnextRELOCATIONDIRECTORY = NULL;
	DWORD lastRELOCATIONDIRECTORYaddr = 1;
	DWORD lastvirtualaddr = 1;
	int kuai = 0;
	pNtHeaders = FileToNtHeader(pFileBuffer);
	
	pRELOCATIONDIRECTORY = PIMAGE_BASE_RELOCATION(RVAtoFOA(pNtHeaders->OptionalHeader.DataDirectory[5].VirtualAddress, pFileBuffer)+ (DWORD)pFileBuffer);
	pnextRELOCATIONDIRECTORY = pRELOCATIONDIRECTORY;
	printf("******************************\n");
	printf("重定位表内容\n");
	//lastvirtualaddr = pRELOCATIONDIRECTORY->VirtualAddress;
	while (lastvirtualaddr > 0) 
	{
		kuai++;
		pRELOCATIONDIRECTORY = pnextRELOCATIONDIRECTORY;
		DWORD numofsetion = (pRELOCATIONDIRECTORY->SizeOfBlock - 8) / 2;
		printf("块%x的地址是%x,大小是%x,块的数量是%x\n", kuai,pRELOCATIONDIRECTORY->VirtualAddress,pRELOCATIONDIRECTORY->SizeOfBlock,numofsetion);
		showRELOCATIONsetion(numofsetion, (WORD*)((DWORD)pRELOCATIONDIRECTORY + 8), (DWORD)pRELOCATIONDIRECTORY->VirtualAddress,pFileBuffer);



		lastRELOCATIONDIRECTORYaddr = (DWORD)pRELOCATIONDIRECTORY+ pRELOCATIONDIRECTORY->SizeOfBlock;//下一个块的地址是文件中的地址加块大小
		pnextRELOCATIONDIRECTORY = (PIMAGE_BASE_RELOCATION)lastRELOCATIONDIRECTORYaddr;
		lastvirtualaddr = pnextRELOCATIONDIRECTORY->VirtualAddress;

		
	}
	//pRELOCATIONDIRECTORY->VirtualAddress;

}

/*
导出表和重定位表迁移测试
*/
LPVOID removeDIRECTORY(LPVOID  pFileBuffer) {
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	PIMAGE_SECTION_HEADER pSectionHeaderBase = NULL;
	LPVOID start = NULL;
	PIMAGE_EXPORT_DIRECTORY exportDIRECTORY = NULL;
	pNtHeaders = FileToNtHeader(pFileBuffer);
	pSectionHeaderBase = LocateSectionBase(pFileBuffer);
	DWORD addrofnamervafirst = 0;

	exportDIRECTORY = (PIMAGE_EXPORT_DIRECTORY)pNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress;
	exportDIRECTORY = (PIMAGE_EXPORT_DIRECTORY)RVAtoFOA((DWORD)exportDIRECTORY, pFileBuffer);
	//导出表现在的文件地址+pfilebuffer
	PIMAGE_EXPORT_DIRECTORY exportDIRECTORYfilebuffer = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)exportDIRECTORY + (DWORD)pFileBuffer);


	//DWORD SizeOfHeadersmem = pSectionHeaderBase->VirtualAddress;
	//找最后一个节
	PIMAGE_SECTION_HEADER pLaswSectionHeaderBase = PIMAGE_SECTION_HEADER((BYTE*)pSectionHeaderBase + (DWORD)(0x28 * (pNtHeaders->FileHeader.NumberOfSections - 1)));
	//找最后一个节的开始地址
	start = (LPVOID)(pLaswSectionHeaderBase->PointerToRawData + (DWORD)pFileBuffer);
	LPVOID starttest = (LPVOID)(pLaswSectionHeaderBase->PointerToRawData + (DWORD)pFileBuffer);//记录内存空间中复制开始的地址

	//复制AddressOfFunctions 
	DWORD AddressOfFunctionssize = exportDIRECTORYfilebuffer->NumberOfFunctions * 4;//大小
	//计算rva
	DWORD AddressOfFunctionsrva = (DWORD)pLaswSectionHeaderBase->VirtualAddress + (DWORD)start - (DWORD)starttest;
	//AddressOfFunctions 起始文件地址
	DWORD* tureAddressOfFunctions = (DWORD*)((DWORD)pFileBuffer + RVAtoFOA(exportDIRECTORYfilebuffer->AddressOfFunctions, pFileBuffer));
	memcpy(start, tureAddressOfFunctions, AddressOfFunctionssize);

	//三步：复制AddressOfNameOrdinals
	start = (LPVOID)((DWORD)start + AddressOfFunctionssize);
	DWORD AddressOfNameOrdinalsrva = (DWORD)pLaswSectionHeaderBase->VirtualAddress + (DWORD)start - (DWORD)starttest;
	DWORD AddressOfNameOrdinalssize = exportDIRECTORYfilebuffer->NumberOfNames * 2;
	//AddressOfNameOrdinals的起始文件地址
	WORD* tureAddressOfNameOrdinals = (WORD*)((DWORD)pFileBuffer + RVAtoFOA(exportDIRECTORYfilebuffer->AddressOfNameOrdinals, pFileBuffer));
	memcpy(start, tureAddressOfNameOrdinals, AddressOfNameOrdinalssize);

	//四步：复制AddressOfNames
	start = (LPVOID)((DWORD)start + AddressOfNameOrdinalssize);
	DWORD AddressOfNamesrva = (DWORD)pLaswSectionHeaderBase->VirtualAddress + (DWORD)start - (DWORD)starttest;
	LPVOID namneaddrstart = start;//记录一下拷贝的名字表的起始地址
	DWORD AddressOfNamessize = exportDIRECTORYfilebuffer->NumberOfNames * 4;
	//AddressOfNames的起始文件地址
	DWORD* tureAddressOfNames = (DWORD*)((DWORD)pFileBuffer + RVAtoFOA(exportDIRECTORYfilebuffer->AddressOfNames, pFileBuffer));
	memcpy(start, tureAddressOfNames, AddressOfNamessize);


	//复制所有的函数名字
	start = (LPVOID)((DWORD)start + AddressOfNamessize);
	printf("******************************拷贝名字表的名字\n");
	for (int i = 0; i < exportDIRECTORYfilebuffer->NumberOfNames; i++) {
		DWORD* tureAddressOfNames = (DWORD*)((DWORD)pFileBuffer + RVAtoFOA(exportDIRECTORYfilebuffer->AddressOfNames, pFileBuffer)) + i;
		DWORD* tureAddressOfNames2 = (DWORD*)((DWORD)namneaddrstart) + i;
		printf("导出表函数名字表文件中地址的值:%x，拷贝后的表里地址的值%x\n", *tureAddressOfNames, *tureAddressOfNames2);

		printf("导出表函数名字表文件地址:%x\n", RVAtoFOA((DWORD)*tureAddressOfNames, pFileBuffer));

		PCHAR Nameaddr = (PCHAR)((BYTE*)RVAtoFOA((DWORD)*tureAddressOfNames, pFileBuffer) + (DWORD)pFileBuffer);
		//CHAR Name[] = { *Nameaddr };
		memcpy(start, Nameaddr, strlen(Nameaddr));


		//修复AddressOfNames
		DWORD namestartyz = (DWORD)start - (DWORD)pFileBuffer;
		//计算nameaddr的rva
		DWORD addrofnamerva = (DWORD)pLaswSectionHeaderBase->VirtualAddress + (DWORD)start - (DWORD)starttest;
		*tureAddressOfNames2 = addrofnamerva;
		start = (LPVOID)((DWORD)start + strlen(Nameaddr));


		if (i == 0)
		{
			addrofnamervafirst = addrofnamerva;
		}
		memset(start, 0x00, 1);//字符串结尾加\00
		start = (LPVOID)((DWORD)start + 1);
		printf("导出表函数大小%x的%x名字:%s,验证修改后的foa正确性%x,对比现在的foa：%x\n", strlen(Nameaddr),i, Nameaddr,RVAtoFOA(*tureAddressOfNames2,pFileBuffer), namestartyz);
	}
	printf("******************************\n");

	//复制IMAGE_EXPORT_DIRECTORY结构
	PIMAGE_EXPORT_DIRECTORY exportDIRECTORYfilebuffercopy = (PIMAGE_EXPORT_DIRECTORY) start;
	memcpy(start, (LPVOID)exportDIRECTORYfilebuffer, sizeof(IMAGE_EXPORT_DIRECTORY));
	start = (LPVOID)((DWORD)start + sizeof(IMAGE_EXPORT_DIRECTORY));


	//
	/*
		第七步：修复IMAGE_EXPORT_DIRECTORY结构中的				
					
		AddressOfFunctions			
					
		AddressOfNameOrdinals			
					
		AddressOfNames			
*/	
	exportDIRECTORYfilebuffercopy->AddressOfFunctions = AddressOfFunctionsrva;
	exportDIRECTORYfilebuffercopy->AddressOfNameOrdinals = AddressOfNameOrdinalsrva;

	exportDIRECTORYfilebuffercopy->AddressOfNames = AddressOfNamesrva;
	//exportDIRECTORYfilebuffercopy->Name = addrofnamervafirst;


	//改数据目录的表指向
	pNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress = (DWORD)pLaswSectionHeaderBase->VirtualAddress+(DWORD)exportDIRECTORYfilebuffercopy -(DWORD)starttest;

	return pFileBuffer;
}

void showDESCRIPTOR(LPVOID pFileBuffer)
{
	PIMAGE_IMPORT_DESCRIPTOR pDescriptor = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	PIMAGE_IMPORT_BY_NAME pImportbyname = NULL;
	PIMAGE_IMPORT_DESCRIPTOR pDescriptorture = NULL;
	PIMAGE_IMPORT_BY_NAME namefuction = NULL;




	pNtHeaders = FileToNtHeader(pFileBuffer);
	//定位导入表
	pDescriptor = (PIMAGE_IMPORT_DESCRIPTOR) pNtHeaders->OptionalHeader.DataDirectory[1].VirtualAddress;
	//此时在内存中的地址要加pFileBuffer
	pDescriptorture = PIMAGE_IMPORT_DESCRIPTOR (RVAtoFOA((DWORD)pDescriptor,pFileBuffer)+(DWORD)pFileBuffer);
	
	//遍历导入表
	while (*((DWORD*)pDescriptorture) != 0)
	{
		printf("******************************\n");
		//输出dll名字
		printf("dll名字为%s\n", (RVAtoFOA(pDescriptorture->Name, pFileBuffer) + (DWORD)pFileBuffer));
		
		//遍历OriginalFirstThunk
		DWORD* startThunk =(DWORD*) (RVAtoFOA((DWORD)pDescriptorture->OriginalFirstThunk, pFileBuffer) + (DWORD)pFileBuffer);
		printf("OriginalFirstThunk内容：\n");
		while (*startThunk != 0)
		{
			if ((* startThunk & 0x80000000) == 0)

			{
				namefuction = (PIMAGE_IMPORT_BY_NAME)(RVAtoFOA(*startThunk, pFileBuffer)+(DWORD)pFileBuffer);
				PCHAR Namefu = (PCHAR)namefuction->Name;
				printf("IMAGE_IMPORT_BY_NAME地址%x,函数名字：%s\n", *startThunk,Namefu);

			}
			else {
				printf("函数的序号%x\n", *startThunk & 0x7FFFFFFF);
			}


			//startThunk = 0;
			startThunk = startThunk + 1;
		}

		//遍历FirstThunk

		DWORD* startFirstThunk = (DWORD*)(RVAtoFOA((DWORD)pDescriptorture->FirstThunk, pFileBuffer) + (DWORD)pFileBuffer);
		printf("FirstThunk内容：\n");
		while (*startFirstThunk != 0)
		{
			if ((*startFirstThunk & 0x80000000) == 0)

			{
				namefuction = (PIMAGE_IMPORT_BY_NAME)(RVAtoFOA(*startFirstThunk, pFileBuffer) + (DWORD)pFileBuffer);
				PCHAR Namefu = (PCHAR)namefuction->Name;
				printf("IMAGE_IMPORT_BY_NAME地址%x,函数名字：%s\n", *startFirstThunk, Namefu);

			}
			else {
				printf("函数的序号%x\n", *startFirstThunk & 0x7FFFFFFF);
			}


			//startThunk = 0;
			startFirstThunk = startFirstThunk + 1;
		}
		pDescriptorture = pDescriptorture + 1;
	}



}

void showBOUND_IMPORT_DESCRIPTOR(LPVOID pFileBuffer)
{
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pDESCRIPTOR = NULL;
	PIMAGE_BOUND_FORWARDER_REF pFORWARDER_REF = NULL;

	printf("******************************\n");
	printf("********绑定导入表解析********\n");
	pNtHeaders = FileToNtHeader(pFileBuffer);
	if (pNtHeaders->OptionalHeader.DataDirectory[11].VirtualAddress == 0) {
		return;
	}
	pDESCRIPTOR = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)(RVAtoFOA(pNtHeaders->OptionalHeader.DataDirectory[11].VirtualAddress, pFileBuffer)+(DWORD)pFileBuffer);
	DWORD startoffer = (DWORD)pDESCRIPTOR;
	PCHAR name = NULL;
	while (*(DWORD*)pDESCRIPTOR != 0)
	{

		name = (PCHAR)startoffer + pDESCRIPTOR->OffsetModuleName;
		printf("时间戳%x名字%s,NumberOfModule数量%x\n", pDESCRIPTOR->TimeDateStamp,name,pDESCRIPTOR->NumberOfModuleForwarderRefs);
		if (pDESCRIPTOR->NumberOfModuleForwarderRefs != 0)
		{
			printf("存在NumberOfModuleForwarderRefs结构：\n");
			pDESCRIPTOR = pDESCRIPTOR + 1;
			for (int i= 0; i < pDESCRIPTOR->NumberOfModuleForwarderRefs; i++)
			{

				PIMAGE_BOUND_FORWARDER_REF pFORWARDER_REF = (PIMAGE_BOUND_FORWARDER_REF)pDESCRIPTOR;
				name = (PCHAR)startoffer + pFORWARDER_REF->OffsetModuleName;
				printf("时间戳%x名字%s\n", pFORWARDER_REF->TimeDateStamp, name);
				pDESCRIPTOR = pDESCRIPTOR + 1;
			}
			printf("NumberOfModuleForwarderRefs结构结束\n");

		}
		pDESCRIPTOR = pDESCRIPTOR + 1;
	}


	
	
}