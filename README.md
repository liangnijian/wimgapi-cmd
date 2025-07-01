# wimgapi-cmd
调用 wimgapi.dll 来安装、查询镜像信息的工具

## 命令用法：


### 安装镜像：
```shell
-install 镜像路径 镜像序号 安装路径

示例：
wimgapi-cmd.exe -install K:\sources\install.wim 3 C:
```

### 查询镜像里有几个系统：
```shell
-info 镜像路径

示例：
wimgapi-cmd.exe -info K:\sources\install.wim
```

### 查询镜像信息：
```shell
-info 镜像路径 镜像序号

示例：
wimgapi-cmd.exe -info K:\sources\install.wim 3
```

### 备份系统：
```shell
-pack 压缩率 系统盘 备份路径 镜像名称

示例：
wimgapi-cmd.exe -pack fast C: "D:\系统备份\Win 10.wim" "Windows 10 专业版"
```
