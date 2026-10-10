#!/usr/bin/env python3
# KeelShim - Windows 7 user-mode UI translation for the Windows 10 kernel
# Copyright (C) 2026 Kevin Dalli <projectkeel@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
r"""Generate build/Keel.sln + build/vs/*.vcxproj so the tree builds natively in
Visual Studio 2026 Community on Windows 11 25H2 (MSBuild, no CMake needed).

Usage (on the Windows box):
    powershell -ExecutionPolicy Bypass -File tools\vs2026-setup.ps1
                                        # one-stop provisioning for VS2026 Community
                                        # on Windows 11 25H2 (b26300+): winget install
                                        # of missing prerequisites, Detours import libs,
                                        # GUID cache refresh, solution smoke test
    py -3 tools\gen-vs2026-sln.py       # regenerate after editing CMakeLists.txt
    msbuild build\Keel.sln /p:Configuration=Debug /p:Platform=x64
    msbuild build\Keel.sln /p:Configuration=Debug /p:Platform=Win32   (x86 side)

Project GUIDs are stable across regenerations via build\project-guids.json, so
per-project IDE state (.vcxproj.user: startup project, debug arguments) never
goes stale even when source lists move around.

Design notes:
  * Mirrors src/CMakeLists.txt (x64) and src32/CMakeLists.txt (Win32): same
    sources, defines, /W4 /permissive- /Zc:__cplusplus /utf-8 /guard:cf, static
    CRT, detours import lib from %KEEL_TOOLS%\detours (setup-toolchain.ps1).
  * PlatformToolset = v145 (VS2026 / Dev18 MSVC toolset). Override per machine:
    msbuild /p:VctoolsVersion=v144 — build/Directory.Build.props honours it.
  * WindowsTargetPlatformVersion = 10.0 → newest installed SDK (the Win11 SDK
    provisioned by setup-toolchain.ps1 / bundled with VS2026 on b26300+).
  * keeldrv.sys: native KMDF link flags matching src/keeldrv/CMakeLists.txt.
    Recent Win11 WDKs ship km libs only for x64/arm64/arm64ec depending on the
    release; Directory.Build.props auto-picks whichever exists and the project
    errors clearly if the requested platform's libs are missing (ARM64EC config
    included so the driver still builds on ARM64EC-only kits).
  * VS output lands in out\vs\<Config>\<target>\ so it never collides with the
    Ninja flow's out\debug / out\release trees.
"""
import os, re, sys, uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = os.path.join(ROOT, 'build')
VSDIR = os.path.join(BUILD, 'vs')

GUID_SOLUTION = '{7B7A52E4-9C3F-4D2B-8A61-5E2F1D0C9B8A}'
VCXPROJ_TYPE = '{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}'
FOLDER_TYPE = '{2150E333-8FDC-42A3-9474-1A3956D46DE8}'

# Stable project GUIDs. uuid5(name) is already deterministic, but if a source
# list moves between CMake targets the hash changes and VS silently orphans the
# per-project .vcxproj.user state (startup project, debug args). So we cache
# name -> guid in build/project-guids.json: existing entries are reused verbatim,
# new projects get uuid5-of-a-fresh-random seed (which then stays pinned too).
GUID_CACHE_FILE = os.path.join(BUILD, 'project-guids.json')
_GUIDS = {}

def load_guid_cache():
    try:
        import json
        with open(GUID_CACHE_FILE, encoding='utf-8') as f:
            data = json.load(f)
        for k, v in data.items():
            if isinstance(v, str) and re.fullmatch(r'\{[0-9A-Fa-f-]{36}\}', v):
                _GUIDS[k] = v.upper()
    except (OSError, ValueError):
        pass   # first run / hand-deleted cache: fall back to derived GUIDs

def save_guid_cache():
    import json
    with open(GUID_CACHE_FILE, 'w', encoding='utf-8', newline='\r\n') as f:
        json.dump(_GUIDS, f, indent=2, sort_keys=True)
        f.write('\n')

def guid_of(key):
    g = _GUIDS.get(key)
    if not g:
        g = '{' + str(uuid.uuid5(uuid.NAMESPACE_URL, 'keel-project/' + key)).upper() + '}'
        _GUIDS[key] = g
    return g

def folder_guid(f):
    return '{' + str(uuid.uuid5(uuid.NAMESPACE_URL, 'keel-folder/' + f)).upper() + '}'

def rel(p):
    return os.path.relpath(p, VSDIR).replace('/', '\\')

def xml_escape(s):
    return s.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

def parse_cml(path):
    txt = open(path, encoding='utf-8').read()
    txt = '\n'.join(l for l in txt.splitlines() if not l.strip().startswith('#'))
    targets = {}
    pat = r'add_(library|executable)\s*\(\s*([A-Za-z0-9_]+)((?:\s+(?:SHARED|STATIC|MODULE|WIN32|EXCLUDE_FROM_ALL))*)\s+([^)]*)\)'
    for m in re.finditer(pat, txt, re.S):
        name, kind, args = m.group(2), (m.group(3) or ''), m.group(4).split()
        srcs = [a for a in args if re.search(r'\.(cpp|c|cc|cxx|h|hpp|def|rc)$', a)]
        seen, ordered = set(), []
        for s in srcs:
            n = os.path.normpath(os.path.join(os.path.dirname(path), s))
            if n not in seen:
                seen.add(n); ordered.append(n)
        targets[name] = dict(shared='SHARED' in kind, static='STATIC' in kind,
                             win32exe='WIN32' in kind, srcs=ordered)
    return targets

BASE_DEFINES = ['UNICODE', '_UNICODE', '_WIN32_WINNT=0x0A00', 'WINVER=0x0A00',
                'NTDDI_VERSION=0x0A000009', 'WIN32_LEAN_AND_MEAN', 'NOMINMAX']

DRV_CHECK_TARGET = '''  <Target Name="KeelCheckDrvPlatform" BeforeTargets="PrepareForBuild">
    <Error Condition="'$(Platform)'=='x64' And '$(KeelDrvArch)'=='arm64ec'" Text="keeldrv: this WDK ships no x64 km libraries (only arm64ec). Build the ARM64EC configuration of keeldrv, or install a WDK with x64 km libs." />
    <Error Condition="'$(Platform)'=='ARM64EC' And '$(KeelDrvArch)'!='arm64ec'" Text="keeldrv: no arm64ec km libraries found under $(KeelKitsRoot)\\Lib\\$(KeelSdkVer)\\km" />
    <Message Importance="high" Text="keeldrv arch=$(KeelDrvArch) sdk=$(KeelSdkVer) kmdf=$(KeelKmdf) kits=$(KeelKitsRoot)" />
  </Target>
'''

def vcxproj(name, *, cfgtype, plats, target_name=None, target_ext=None,
            srcs=(), defines=(), includes=(), libs=(), libdirs=(),
            module_def=None, subsystem=None, entry=None,
            nodefaultlibs=False, c_style=False, kernel=False,
            link_flags=(), project_refs=(), sdk_version='10.0'):
    E = []
    A = E.append
    configs = [(c, p) for p in plats for c in ('Debug', 'RelWithDebInfo')]
    A('<?xml version="1.0" encoding="utf-8"?>')
    A('<Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">')
    A('  <ItemGroup Label="ProjectConfigurations">')
    for c, p in configs:
        A('    <ProjectConfiguration Include="%s|%s">' % (c, p))
        A('      <Configuration>%s</Configuration>' % c)
        A('      <Platform>%s</Platform>' % p)
        A('    </ProjectConfiguration>')
    A('  </ItemGroup>')
    A('  <PropertyGroup Label="Globals">')
    A('    <ProjectGuid>%s</ProjectGuid>' % guid_of(name))
    A('    <RootNamespace>%s</RootNamespace>' % name)
    A('    <WindowsTargetPlatformVersion>%s</WindowsTargetPlatformVersion>' % sdk_version)
    A('  </PropertyGroup>')
    A('  <Import Project="$(VCTargetsPath)\\Microsoft.Cpp.Default.props" />')
    for c, p in configs:
        A('  <PropertyGroup Condition="\'$(Configuration)|$(Platform)\'==\'%s|%s\'" Label="Configuration">' % (c, p))
        A('    <ConfigurationType>%s</ConfigurationType>' % cfgtype)
        A('    <UseDebugLibraries>%s</UseDebugLibraries>' % ('true' if c == 'Debug' else 'false'))
        A('    <PlatformToolset>$(KeelToolset)</PlatformToolset>')
        A('    <CharacterSet>Unicode</CharacterSet>')
        if not kernel:
            A('    <SpectreMitigation>Spectre</SpectreMitigation>')
        A('  </PropertyGroup>')
    A('  <Import Project="$(VCTargetsPath)\\Microsoft.Cpp.props" />')
    if kernel:
        A(DRV_CHECK_TARGET.rstrip('\n'))
    A('  <PropertyGroup>')
    A('    <OutDir>$(KEEL_ROOT)out\\vs\\$(Configuration)\\%s\\</OutDir>' % name)
    A('    <IntDir>$(KEEL_ROOT)build\\obj\\%s\\$(Configuration)\\$(Platform)\\</IntDir>' % name)
    if target_name:
        A('    <TargetName>%s</TargetName>' % target_name)
    if target_ext:
        A('    <TargetExt>%s</TargetExt>' % target_ext)
    A('  </PropertyGroup>')
    A('  <ItemDefinitionGroup>')
    for c, _ in configs:
        cond = "'$(Configuration)'=='%s'" % c
        dbg = c == 'Debug'
        A('    <ClCompile Condition="%s">' % cond)
        A('      <WarningLevel>Level4</WarningLevel>')
        A('      <TreatWarningAsError>false</TreatWarningAsError>')
        if not c_style:
            A('      <LanguageStandard>stdcpp20</LanguageStandard>')
        A('      <ConformanceMode>true</ConformanceMode>')
        defs = list(BASE_DEFINES) + list(defines)
        if kernel:
            defs += ['_WIN64', '_AMD64_', 'AMD64', 'POOL_NX_OPTIN=1', 'DEPRECATE_DDK_FUNCTIONS=1',
                     'KMDF_VERSION_MAJOR=$(KeelKmdfMajor)', 'KMDF_VERSION_MINOR=$(KeelKmdfMinor)']
        A('      <PreprocessorDefinitions>%s;%%(PreprocessorDefinitions)</PreprocessorDefinitions>' % ';'.join(defs))
        A('      <BufferSecurityCheck>true</BufferSecurityCheck>')
        A('      <ControlFlowGuard>Guard</ControlFlowGuard>')
        A('      <RuntimeLibrary>%s</RuntimeLibrary>' % ('MultiThreadedDebug' if dbg else 'MultiThreaded'))
        A('      <Optimization>%s</Optimization>' % ('Disabled' if dbg else 'MaxSpeed'))
        A('      <DebugInformationFormat>ProgramDatabase</DebugInformationFormat>')
        opts = ['/utf-8', '/Zc:__cplusplus']
        if kernel:
            opts += ['/kernel', '/GS', '/Gy', '/Gw', '/Oi', '/Zc:wchar_t-', '/GR-', '/EHs-c-',
                     '/Qspectre', '/wd4201', '/wd4214', '/wd4996']
            A('      <CompileAs>CompileAsC</CompileAs>')
        A('      <AdditionalOptions>%s %%(AdditionalOptions)</AdditionalOptions>' % ' '.join(opts))
        incs = list(includes)
        if kernel:
            incs += ['$(KeelKmInc)', '$(KeelKmCrtInc)', '$(KeelKmSharedInc)', '$(KeelWdfInc)']
        if incs:
            A('      <AdditionalIncludeDirectories>%s;%%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>' % ';'.join(incs))
        A('    </ClCompile>')
        if cfgtype != 'StaticLibrary':
            A('    <Link Condition="%s">' % cond)
            A('      <SubSystem>%s</SubSystem>' % (subsystem or ('Native' if kernel else ('Console' if cfgtype == 'Application' else 'Windows'))))
            A('      <GenerateDebugInformation>true</GenerateDebugInformation>')
            if entry:
                A('      <EntryPointSymbol>%s</EntryPointSymbol>' % entry)
            if nodefaultlibs:
                A('      <IgnoreAllDefaultLibraries>true</IgnoreAllDefaultLibraries>')
            ld = list(libs)
            if kernel:
                ld += ['ntoskrnl.lib', 'hal.lib', 'wmilib.lib', 'BufferOverflowFastFailK.lib',
                       'WdfLdr.lib', 'WdfDriverEntry.lib', 'ntstrsafe.lib', 'wdmsec.lib']
            if ld:
                A('      <AdditionalDependencies>%s;%%(AdditionalDependencies)</AdditionalDependencies>' % ';'.join(ld))
            ldirs = list(libdirs)
            if kernel:
                ldirs += ['$(KeelKmLib)', '$(KeelWdfLib)']
            if ldirs:
                A('      <AdditionalLibraryDirectories>%s;%%(AdditionalLibraryDirectories)</AdditionalLibraryDirectories>' % ';'.join(ldirs))
            lf = list(link_flags)
            if kernel:
                lf += ['/DRIVER', '/SUBSYSTEM:NATIVE,10.0', '/ENTRY:FxDriverEntry', '/NODEFAULTLIB',
                       '/INCREMENTAL:NO', '/RELEASE', '/NXCOMPAT', '/DYNAMICBASE', '/MANIFEST:NO',
                       '/INTEGRITYCHECK', '/guard:cf', '/MERGE:_TEXT=.text', '/MERGE:_PAGE=PAGE',
                       '/SECTION:INIT,d', '/OPT:REF', '/OPT:ICF', '/DEBUG', '/IGNORE:4078', '/IGNORE:4254']
            else:
                lf += ['/DEBUG', '/guard:cf']
            A('      <AdditionalOptions>%s %%(AdditionalOptions)</AdditionalOptions>' % ' '.join(lf))
            if module_def:
                A('      <ModuleDefinitionFile>%s</ModuleDefinitionFile>' % rel(module_def))
            A('    </Link>')
    A('  </ItemDefinitionGroup>')
    A('  <ItemGroup>')
    for s in srcs:
        e = os.path.splitext(s)[1].lower()
        rp = rel(s)
        if e in ('.cpp', '.c', '.cc', '.cxx'):
            A('    <ClCompile Include="%s" />' % rp)
        elif e in ('.h', '.hpp'):
            A('    <ClInclude Include="%s" />' % rp)
        elif e == '.rc':
            A('    <ResourceCompile Include="%s" />' % rp)
        elif e == '.def':
            A('    <None Include="%s" />' % rp)
    A('  </ItemGroup>')
    if project_refs:
        A('  <ItemGroup>')
        for ref_file, ref_name in project_refs:
            A('    <ProjectReference Include="%s"><Project>%s</Project></ProjectReference>'
              % (ref_file, guid_of(ref_name)))
        A('  </ItemGroup>')
    A('  <Import Project="$(VCTargetsPath)\\Microsoft.Cpp.targets" />')
    A('</Project>')
    return '\n'.join(E) + '\n'

def solution(projects, folders):
    L = []
    A = L.append
    A('Microsoft Visual Studio Solution File, Format Version 12.00')
    A('# Visual Studio Version 18')
    A('VisualStudioVersion = 18.0.1.1')
    A('MinimumVisualStudioVersion = 10.0.40219.1')
    for name, path in projects:
        A('Project("%s") = "%s", "%s", "%s"' % (VCXPROJ_TYPE, name, xml_escape(path), guid_of(name)))
        A('EndProject')
    for f in folders:
        A('Project("%s") = "%s", "%s", "%s"' % (FOLDER_TYPE, f, f, folder_guid(f)))
        A('EndProject')

    A('Project("%s") = "Solution Items", "Solution Items", "%s"'
      % (FOLDER_TYPE, folder_guid('Solution Items')))
    A('ProjectSection(SolutionItems) = preProject')
    A('\t..\\tools\\gen-vs2026-sln.py = ..\\tools\\gen-vs2026-sln.py')
    A('\t..\\tools\\vs2026-setup.ps1 = ..\\tools\\vs2026-setup.ps1')
    A('\t..\\tools\\setup-toolchain.ps1 = ..\\tools\\setup-toolchain.ps1')
    A('\tDirectory.Build.props = Directory.Build.props')
    A('\tproject-guids.json = project-guids.json')
    A('\t..\\README-VS.md = ..\\README-VS.md')
    A('\t..\\README-ISO.md = ..\\README-ISO.md')
    A('\t..\\tools\\make-keel-iso.ps1 = ..\\tools\\make-keel-iso.ps1')
    A('EndProjectSection')
    A('EndProject')
    A('Global')
    A('\tGlobalSection(SolutionConfigurationPlatforms) = preSolution')
    confplats = set()
    for name, _ in projects:
        g = guid_of(name)
        for c in ('Debug', 'RelWithDebInfo'):
            for p in PROJ_PLATS[name]:
                confplats.add((c, p))
    for c, p in sorted(confplats):
        A('\t\t%s|%s = %s|%s' % (c, p, c, p))
    A('\tEndGlobalSection')
    A('\tGlobalSection(ProjectConfigurationPlatforms) = postSolution')
    for name, _ in projects:
        g = guid_of(name)
        for c in ('Debug', 'RelWithDebInfo'):
            for p in PROJ_PLATS[name]:
                A('\t\t%s.%s|%s.ActiveCfg = %s|%s' % (g, c, p, c, p))
                A('\t\t%s.%s|%s.Build.0 = %s|%s' % (g, c, p, c, p))
    A('\tEndGlobalSection')
    A('\tGlobalSection(SolutionProperties) = preSolution')
    A('\t\tHideSolutionNode = FALSE')
    A('\tEndGlobalSection')
    A('\tGlobalSection(NestedProjects) = preSolution')
    for f, members in folders.items():
        for m in members:
            A('\t\t%s = %s' % (guid_of(m), folder_guid(f)))
    A('\tEndGlobalSection')
    A('\tGlobalSection(ExtensibilityGlobals) = postSolution')
    A('\t\tSolutionGuid = %s' % GUID_SOLUTION)
    A('\tEndGlobalSection')
    A('EndGlobal')
    return '\n'.join(L) + '\n'

PROPS_XML = r'''<?xml version="1.0" encoding="utf-8"?>
<Project>
  <!-- One place to pick the compiler for this solution.
       VS2026 (Dev18) ships toolset v145; override per machine with
       msbuild /p:VctoolsVersion=v144 (or edit KeelToolset here). -->
  <PropertyGroup>
    <KeelToolset Condition="'$(KeelToolset)'=='' And '$(VctoolsVersion)'!=''">$(VctoolsVersion)</KeelToolset>
    <KeelToolset Condition="'$(KeelToolset)'==''">v145</KeelToolset>
    <!-- repo root: build\ -> ..\ ; KEEL_ROOT must end with a backslash -->
    <KEEL_ROOT Condition="'$(KEEL_ROOT)'==''">$([MSBuild]::EnsureTrailingSlash('$(MSBuildThisFileDirectory)..\'))</KEEL_ROOT>
    <!-- tools root (detours lives here; env.ps1/setup-toolchain.ps1 use the same var) -->
    <KEEL_TOOLS Condition="'$(KEEL_TOOLS)'=='' And '$(DETOURS_ROOT)'!=''">$([MSBuild]::RemoveDirectoryNameEndingSlash($(DETOURS_ROOT)))</KEEL_TOOLS>
    <KEEL_TOOLS Condition="'$(KEEL_TOOLS)'=='' And $env(DETOURS_ROOT)!=''">$([MSBuild]::RemoveDirectoryNameEndingSlash($env(DETOURS_ROOT)))</KEEL_TOOLS>
    <KEEL_TOOLS Condition="'$(KEEL_TOOLS)'==''">$([MSBuild]::EnsureTrailingSlash($env(KEEL_TOOLS)))</KEEL_TOOLS>
    <KEEL_TOOLS Condition="'$(KEEL_TOOLS)'==''">C:\Keel-tools</KEEL_TOOLS>
    <DETOURS_LIB64 Condition="Exists('$(KEEL_TOOLS)detours\lib.X64\detours.lib')">$(KEEL_TOOLS)detours\lib.X64\detours.lib</DETOURS_LIB64>
    <DETOURS_INC Condition="Exists('$(KEEL_TOOLS)detours\include\detours.h')">$(KEEL_TOOLS)detours\include</DETOURS_INC>
  </PropertyGroup>

  <!-- Windows Kits root + newest installed SDK version (same rule as tools\env.ps1) -->
  <PropertyGroup>
    <KeelKitsRoot Condition="'$(WindowsSdkDir)'!='' And Exists('$(WindowsSdkDir)')">$(WindowsSdkDir.TrimEnd('\'))</KeelKitsRoot>
    <KeelKitsRoot Condition="'$(KeelKitsRoot)'=='' And Exists('$(KEEL_TOOLS)msvc\Windows Kits\10')">$(KEEL_TOOLS)msvc\Windows Kits\10</KeelKitsRoot>
    <KeelKitsRoot Condition="'$(KeelKitsRoot)'=='' And Exists('$(ProgramFiles)\Windows Kits\10')">$(ProgramFiles)\Windows Kits\10</KeelKitsRoot>
    <KeelSdkVer Condition="'$(WindowsSDKVersion)'!=''">$(WindowsSDKVersion.TrimEnd('\'))</KeelSdkVer>
  </PropertyGroup>
  <ItemGroup Condition="'$(KeelKitsRoot)'!='' And '$(KeelSdkVer)'==''">
    <_KeelSdkInc Include="$(KeelKitsRoot)\Include\*\km\ntddk.h" />
  </ItemGroup>
  <UsingTask TaskName="_KeelPickVer" TaskFactory="RoslynCodeTaskFactory" AssemblyFile="$(MSBuildToolsPath)\Microsoft.Build.Tasks.Core.dll">
    <ParameterGroup>
      <Candidates ParameterType="Microsoft.Build.Framework.ITaskItem[]" Required="true" />
      <Result OutputParameterType="Microsoft.Build.Framework.ITaskItem" />
    </ParameterGroup>
    <Task xmlns=""><Code Type="Fragment" Language="cs"><![CDATA[
      System.Version best = null; Microsoft.Build.Framework.ITaskItem win = null;
      foreach (var c in Candidates) {
        var m = System.Text.RegularExpressions.Regex.Match(c.ItemSpec, @"(\d+(\.\d+)+)");
        if (!m.Success) continue;
        var v = new System.Version(m.Value);
        if (best == null || v > best) { best = v; win = c; }
      }
      Result = win;
]]></Code></Task>
  </UsingTask>
  <_KeelPickVer Candidates="@(_KeelSdkInc)" Condition="'$(KeelSdkVer)'=='' And '@(_KeelSdkInc)'!=''">
    <Output TaskParameter="Result" ItemName="_KeelSdkWin" />
  </_KeelPickVer>
  <PropertyGroup Condition="'$(KeelSdkVer)'=='' And '@(_KeelSdkWin)'!=''">
    <KeelSdkVer>$([System.Text.RegularExpressions.Regex]::Match('%(_KeelSdkWin.FullPath)', '\d+(\.\d+)+').Value)</KeelSdkVer>
  </PropertyGroup>

  <!-- keeldrv: prefer x64 km libs; fall back to arm64ec (some Win11 WDKs dropped x64 km) -->
  <PropertyGroup Condition="'$(Platform)'=='x64'">
    <KeelDrvArch Condition="'$(KeelKitsRoot)'!='' And Exists('$(KeelKitsRoot)\Lib\$(KeelSdkVer)\km\x64\ntoskrnl.lib')">x64</KeelDrvArch>
    <KeelDrvArch Condition="'$(KeelDrvArch)'=='' And '$(KeelKitsRoot)'!='' And Exists('$(KeelKitsRoot)\Lib\$(KeelSdkVer)\km\arm64ec\ntoskrnl.lib')">arm64ec</KeelDrvArch>
    <KeelDrvArch Condition="'$(KeelDrvArch)'==''">x64</KeelDrvArch>
  </PropertyGroup>
  <PropertyGroup Condition="'$(Platform)'=='ARM64EC'">
    <KeelDrvArch>arm64ec</KeelDrvArch>
  </PropertyGroup>
  <PropertyGroup>
    <KeelKmInc>$(KeelKitsRoot)\Include\$(KeelSdkVer)\km</KeelKmInc>
    <KeelKmCrtInc>$(KeelKitsRoot)\Include\$(KeelSdkVer)\km\crt</KeelKmCrtInc>
    <KeelKmSharedInc>$(KeelKitsRoot)\Include\$(KeelSdkVer)\shared</KeelKmSharedInc>
    <KeelKmLib>$(KeelKitsRoot)\Lib\$(KeelSdkVer)\km\$(KeelDrvArch)</KeelKmLib>
    <KeelWdfLibRoot>$(KeelKitsRoot)\Lib\wdf\kmdf\$(KeelDrvArch)</KeelWdfLibRoot>
  </PropertyGroup>
  <ItemGroup Condition="Exists('$(KeelWdfLibRoot)')">
    <_KeelWdf Include="$(KeelWdfLibRoot)\*\WdfDriverEntry.lib" />
  </ItemGroup>
  <_KeelPickVer Candidates="@(_KeelWdf)" Condition="'@(_KeelWdf)'!=''">
    <Output TaskParameter="Result" ItemName="_KeelWdfWin" />
  </_KeelPickVer>
  <PropertyGroup>
    <KeelKmdf Condition="'@(_KeelWdfWin)'!=''">$([System.Text.RegularExpressions.Regex]::Match('%(_KeelWdfWin.FullPath)', 'kmdf.(\d+\.\d+)').Groups[1].Value)</KeelKmdf>
    <KeelKmdfMajor Condition="'$(KeelKmdf)'!=''">$(KeelKmdf.Split('.')[0])</KeelKmdfMajor>
    <KeelKmdfMinor Condition="'$(KeelKmdf)'!=''">$(KeelKmdf.Split('.')[1])</KeelKmdfMinor>
    <KeelWdfInc Condition="'$(KeelKmdf)'!=''">$(KeelKitsRoot)\Include\wdf\kmdf\$(KeelKmdf)</KeelWdfInc>
    <KeelWdfLib Condition="'$(KeelKmdf)'!=''">$(KeelWdfLibRoot)\$(KeelKmdf)</KeelWdfLib>
  </PropertyGroup>
</Project>
'''

PROJ_PLATS = {}   # name -> [platforms], filled by main(); used by solution()

def main():
    os.makedirs(VSDIR, exist_ok=True)
    load_guid_cache()
    x64 = parse_cml(os.path.join(ROOT, 'src', 'CMakeLists.txt'))
    for sub in ('keelcommon', 'keelshim', 'keeltsf', 'keelldr', 'keelexp', 'keeltest',
                'keelbroker', 'keeluxsms', 'keelr2test', 'keeldxprobe', 'keeldcprobe',
                'keeldcomp', 'keeldrv'):
        x64.update(parse_cml(os.path.join(ROOT, 'src', sub, 'CMakeLists.txt')))
    x86 = parse_cml(os.path.join(ROOT, 'src32', 'CMakeLists.txt'))

    detours_lib = r'$(KEEL_TOOLS)detours\lib.X64\detours.lib'
    detours_inc = r'$(KEEL_TOOLS)detours\include'
    common_inc = rel(os.path.join(ROOT, 'src', 'keelcommon', 'include'))
    shim_inc = rel(os.path.join(ROOT, 'src', 'keelshim', 'include'))

    projects = []          # (name, sln-relative path)
    folders = {'x64': [], 'x86': [], 'driver': []}

    def emit(fname, folder, content, plats):
        open(os.path.join(VSDIR, fname), 'w', encoding='utf-8', newline='\r\n').write(content)
        name = fname[:-len('.vcxproj')]
        projects.append((name, 'vs\\' + fname))
        PROJ_PLATS[name] = plats
        folders[folder].append(name)

    # ---- x64 ----
    t = x64['keelcommon']
    emit('keelcommon.vcxproj', 'x64', vcxproj('keelcommon', cfgtype='StaticLibrary', plats=['x64'],
         srcs=t['srcs'], includes=[common_inc], libs=['advapi32.lib', 'version.lib']), ['x64'])

    t = x64['keelshim']
    defs = [s for s in t['srcs'] if s.endswith('.def')]
    emit('keelshim.vcxproj', 'x64', vcxproj('keelshim', cfgtype='DynamicLibrary', plats=['x64'],
         srcs=t['srcs'], includes=[shim_inc, common_inc, detours_inc],
         project_refs=[('keelcommon.vcxproj', 'keelcommon')],
         libs=[detours_lib, 'user32.lib', 'gdi32.lib', 'advapi32.lib', 'ole32.lib',
               'shell32.lib', 'kernel32.lib', 'version.lib'],
         module_def=defs[0] if defs else None), ['x64'])

    t = x64['keeltsf']
    emit('keeltsf.vcxproj', 'x64', vcxproj('keeltsf', cfgtype='DynamicLibrary', plats=['x64'],
         srcs=t['srcs'], includes=[detours_inc], libs=[detours_lib]), ['x64'])

    t = x64['keelldr']
    emit('keelldr.vcxproj', 'x64', vcxproj('keelldr', cfgtype='Application', plats=['x64'],
         srcs=t['srcs'], includes=[common_inc, detours_inc],
         project_refs=[('keelcommon.vcxproj', 'keelcommon')],
         libs=[detours_lib, 'shlwapi.lib'], subsystem='Console'), ['x64'])

    t = x64['keelexp']
    emit('keelexp.vcxproj', 'x64', vcxproj('keelexp', cfgtype='Application', plats=['x64'],
         srcs=t['srcs'], libs=['shell32.lib'], subsystem='Windows'), ['x64'])

    t = x64['keeltest']
    emit('keeltest.vcxproj', 'x64', vcxproj('keeltest', cfgtype='Application', plats=['x64'],
         srcs=t['srcs'], includes=[common_inc],
         project_refs=[('keelcommon.vcxproj', 'keelcommon')],
         libs=['user32.lib', 'gdi32.lib', 'shlwapi.lib'], subsystem='Windows'), ['x64'])

    for n in ('keelbroker', 'keeluxsms', 'keelr2test'):
        t = x64[n]
        extra = ['user32.lib', 'gdi32.lib'] if n == 'keelbroker' else []
        emit(n + '.vcxproj', 'x64', vcxproj(n, cfgtype='Application', plats=['x64'],
             srcs=t['srcs'], includes=[common_inc],
             project_refs=[('keelcommon.vcxproj', 'keelcommon')],
             libs=extra, subsystem='Console'), ['x64'])

    t = x64['keeldxprobe']
    emit('keeldxprobe.vcxproj', 'x64', vcxproj('keeldxprobe', cfgtype='Application', plats=['x64'],
         srcs=t['srcs'], includes=[common_inc],
         project_refs=[('keelcommon.vcxproj', 'keelcommon')],
         libs=['user32.lib', 'gdi32.lib', 'd3d11.lib', 'dxgi.lib', 'dcomp.lib',
               'opengl32.lib', 'd3d9.lib'], subsystem='Windows'), ['x64'])

    t = x64['keeldcprobe']
    emit('keeldcprobe.vcxproj', 'x64', vcxproj('keeldcprobe', cfgtype='Application', plats=['x64'],
         srcs=t['srcs'], includes=[common_inc],
         project_refs=[('keelcommon.vcxproj', 'keelcommon')],
         libs=['user32.lib', 'd3d11.lib', 'dxgi.lib', 'dcomp.lib'], subsystem='Console'), ['x64'])

    t = x64['keeldcomp']
    defs = [s for s in t['srcs'] if s.endswith('.def')]
    emit('keeldcomp.vcxproj', 'x64', vcxproj('keeldcomp', cfgtype='DynamicLibrary', plats=['x64'],
         target_name='dcomp', srcs=t['srcs'],
         includes=[rel(os.path.join(ROOT, 'src', 'keeldcomp'))],
         module_def=defs[0] if defs else None), ['x64'])

    # ---- driver (x64 + ARM64EC; Directory.Build.props resolves kit roots) ----
    t = x64['keeldrv']
    emit('keeldrv.vcxproj', 'driver', vcxproj('keeldrv', cfgtype='Application',
         plats=['x64', 'ARM64EC'], target_ext='.sys', srcs=t['srcs'],
         c_style=True, kernel=True, entry='FxDriverEntry', nodefaultlibs=True), ['x64', 'ARM64EC'])

    # ---- x86 ----
    for n in ('keelshim32', 'keelldr32', 'keeldxprobe32', 'keelpaint', 'keelpaintm'):
        t = x86[n]
        if n == 'keelshim32':
            cfg, sub, libs = 'DynamicLibrary', 'Windows', []
        elif n == 'keelldr32':
            cfg, sub, libs = 'Application', 'Console', []
        elif n == 'keeldxprobe32':
            cfg, sub, libs = 'Application', 'Windows', \
                ['user32.lib', 'gdi32.lib', 'd3d11.lib', 'dxgi.lib', 'dcomp.lib']
        else:
            cfg, sub, libs = 'Application', 'Windows', \
                ['user32.lib', 'gdi32.lib', 'msimg32.lib', 'comctl32.lib']
        kw = {}
        if n == 'keelpaintm':
            kw['link_flags'] = ['/MANIFEST:EMBED', '/MANIFESTUAC:NO',
                                '/MANIFESTINPUT:' + rel(os.path.join(ROOT, 'src32', 'keelpaint', 'keelpaint.manifest'))]
        emit(n + '.vcxproj', 'x86', vcxproj(n, cfgtype=cfg, plats=['Win32'],
             srcs=t['srcs'], libs=libs, subsystem=sub, **kw), ['Win32'])

    # ---- build/Directory.Build.props + build/Keel.sln + GUID cache ----
    open(os.path.join(BUILD, 'Directory.Build.props'), 'w',
         encoding='utf-8', newline='\r\n').write(PROPS_XML)
    open(os.path.join(BUILD, 'Keel.sln'), 'w',
         encoding='utf-8', newline='\r\n').write(solution(projects, folders))
    save_guid_cache()

    print('wrote build/Keel.sln (%d projects):' % len(projects))
    for name, path in projects:
        print('  %-16s %s [%s]' % (name, path, ','.join(PROJ_PLATS[name])))

if __name__ == '__main__':
    sys.exit(main())
