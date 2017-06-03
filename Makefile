MODULE_NAME=Public.Storage.Manta
MODULE_LICENSE=GPL/LGPL/MPL
MODULE_DIR_NAME=Public_Storage_Manta

release: 
	hg tag -fr tip RELEASE_1.${MIN}
	hg push
	hg archive -r RELEASE_1.${MIN} ${MODULE_DIR_NAME}-1.${MIN}
        rm ${MODULE_DIR_NAME}-1.${MIN}/Makefile
        rm ${MODULE_DIR_NAME}-1.${MIN}/upload_module_version.pike 
        echo "MODULE=$MODULE_NAME" > ${MODULE_DIR_NAME}-1.${MIN}/METADATA.TXT
        echo "VERSION=1.${MIN}" >> ${MODULE_DIR_NAME}-1.${MIN}/METADATA.TXT
        echo "PLATFORM=any/any" >> ${MODULE_DIR_NAME}-1.${MIN}/METADATA.TXT
	tar cvf ${MODULE_DIR_NAME}-1.${MIN}.tar ${MODULE_DIR_NAME}-1.${MIN}
	gzip ${MODULE_DIR_NAME}-1.${MIN}.tar
	rm -rf ${MODULE_DIR_NAME}-1.${MIN}
	pike upload_module_version.pike ${MODULE_NAME} 1.${MIN} "${MODULE_LICENSE}"
