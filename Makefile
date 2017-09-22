CCC = g++
CXX = g++
BASICOPTS = -g -m64 -fPIC
CCFLAGS = $(BASICOPTS)
CXXFLAGS = $(BASICOPTS)
CCADMIN = 


# 定义目标目录。
TARGETDIR_libzwlicensef.so=GNU-amd64-Linux


all: $(TARGETDIR_libzwlicensef.so)/libzwlicensef.so

## 目标： libzwlicensef.so
CCFLAGS_libzwlicensef.so = 
OBJS_libzwlicensef.so =  \
	$(TARGETDIR_libzwlicensef.so)/besencryptf.o


# 链接或归档
SHAREDLIB_FLAGS_libzwlicensef.so = -shared 
$(TARGETDIR_libzwlicensef.so)/libzwlicensef.so: $(TARGETDIR_libzwlicensef.so) $(OBJS_libzwlicensef.so) $(DEPLIBS_libzwlicensef.so)
	$(LINK.cc) $(CCFLAGS_libzwlicensef.so) $(CPPFLAGS_libzwlicensef.so) -o $@ $(OBJS_libzwlicensef.so) $(SHAREDLIB_FLAGS_libzwlicensef.so) $(LDLIBS_libzwlicensef.so)


# 将源文件编译为 .o 文件

$(TARGETDIR_libzwlicensef.so)/besencryptf.o: $(TARGETDIR_libzwlicensef.so) besencryptf.cpp
	$(COMPILE.cc) $(CCFLAGS_libzwlicensef.so) $(CPPFLAGS_libzwlicensef.so) -o $@ besencryptf.cpp



#### 清理目标将会删除所有生成的文件 ####
clean:
	rm -f \
		$(TARGETDIR_libzwlicensef.so)/libzwlicensef.so \
		$(TARGETDIR_libzwlicensef.so)/besencryptf.o
	$(CCADMIN)
	rm -f -r $(TARGETDIR_libzwlicensef.so)


# 创建目标目录（如果需要）
$(TARGETDIR_libzwlicensef.so):
	mkdir -p $(TARGETDIR_libzwlicensef.so)


# 启用依赖关系检查
.KEEP_STATE:
.KEEP_STATE_FILE:.make.state.GNU-amd64-Linux