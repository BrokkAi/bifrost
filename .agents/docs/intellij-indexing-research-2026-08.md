# IntelliJ indexing and find-usages: mechanisms for a Bifrost Rust usage v2

Source: `/home/jonathan/Projects/intellij-community` at commit
`277409ac3905ece64efd598bfeada8fc69fdb4f0` (2025-10-11). All paths below are
repo-relative to that clone.

Legend:
- **[V]** = verified. I read the code and quote the file, class, and method.
- **[I]** = inferred. The code makes it very probable, but I did not read a
  direct proof.

---

## 1. Index storage model

### 1.1 The two maps

`MapReduceIndex` is the base of every file-based index.
File: `platform/util/src/com/intellij/util/indexing/impl/MapReduceIndex.java`.

It holds exactly two storages **[V]** (lines 41-43):

```java
private final IndexStorage<Key, Value> myStorage;              // inverted
private final @Nullable ForwardIndex myForwardIndex;           // forward
private final @Nullable ForwardIndexAccessor<Key, Value> myForwardIndexAccessor;
```

- **Inverted map**: `Key -> ValueContainer<Value>`. A `ValueContainer` is a set
  of `(inputId, value)` pairs. `inputId` is the VFS file id (an `int`).
  See `IndexStorage.addValue(Key, int inputId, Value)` in
  `platform/util/src/com/intellij/util/indexing/impl/IndexStorage.java`.
- **Forward map**: `int inputId -> ByteArraySequence`. The bytes are the
  serialized `Key -> Value` map that the indexer produced for that one file.
  See `ForwardIndex` in
  `platform/util/src/com/intellij/util/indexing/impl/forward/ForwardIndex.java`
  and `MapReduceIndex.updateForwardIndex` (line 317).

The forward map exists for one purpose only: to compute the per-file diff on
the next update. `MapReduceIndex.getKeysDiffBuilder(inputId)` (line 334) reads
the forward entry of that one file and builds an `InputDataDiffBuilder`. **[V]**

### 1.2 Disk structures

Default layout:
`platform/indexing-impl/src/com/intellij/util/indexing/impl/storage/DefaultIndexStorageLayoutProvider.kt`
**[V]**

- Inverted map -> `VfsAwareMapIndexStorage` extends `MapIndexStorage`
  (`platform/util/src/com/intellij/util/indexing/impl/MapIndexStorage.java`),
  which wraps `ValueContainerMap` over a `PersistentMapImpl` (line 139:
  `new PersistentMapImpl<>(builder)`).
- Forward map -> `PersistentMapBasedForwardIndex` (line 65 of the layout
  provider), also a `PersistentMapImpl`.

`PersistentMapImpl`
(`platform/util/src/com/intellij/util/io/PersistentMapImpl.java`) documents its
own shape in the class javadoc **[V]**:

> Particular key is translated via myEnumerator into an int. As part of
> enumeration process for the new key, additional space is reserved in
> myEnumerator.myStorage for offset in ".values" file (myValueStorage) where
> (serialized) value is stored. ... PHM can work in appendable mode: for
> particular key additional calculated chunk of value can be appended to
> ".values" file with the offset of previously calculated chunk.

So one index on disk is: a key enumerator (B-tree, `PersistentBTreeEnumerator`
/ `PersistentEnumerator`), an int-keyed offset table, and a `.values` blob file
with chunk chains. `MapIndexStorage.getIndexStorageFile` appends `.storage`
(line 434).

Both storages read and write through `PagedFileStorage`, which is served by a
shared page cache. `platform/util/src/com/intellij/util/io/PageCacheUtils.java`
**[V]**:

```java
public static final int DEFAULT_PAGE_SIZE = ... 10 * MiB;   // line 25
public static final long FILE_PAGE_CACHES_TOTAL_CAPACITY_BYTES = MathUtil.clamp(
   getLongProperty("file-page-cache.cache-capacity-mb", CpuArch.is32Bit() ? 200 : 600) * MiB, ...);
```

That is a **fixed global budget of about 600 MB of direct (off-heap) memory for
every index storage in the process**. It is a cache over files, not a
materialization. Pages are evicted with the oldest-first policy
(`FilePageCache` class javadoc, lines 44-46). **[V]**

### 1.3 What is in RAM at query time

Not the index. What is in RAM is:

1. A bounded SLRU cache of `ChangeTrackingValueContainer` objects, one entry
   per **key** (not per file), in `MapIndexStorage.myCache`. Created by
   `MapIndexStorageCacheProvider` in
   `platform/util/src/com/intellij/util/indexing/impl/MapIndexStorageCache.kt`
   (`SlruIndexStorageCacheProvider`, protected queue = `cacheSize`, probation =
   `cacheSize / 4`). **[V]**
2. The default `cacheSize` is 1024 keys:
   `FileBasedIndexExtension.DEFAULT_CACHE_SIZE = 1024`
   (`platform/indexing-api/src/com/intellij/util/indexing/FileBasedIndexExtension.java`
   line 56). `IdIndex` overrides to `64 * 1024 = 65536` keys
   (`platform/indexing-impl/src/com/intellij/psi/impl/cache/impl/id/IdIndex.java`
   `getCacheSize`). `StubUpdatingIndex` overrides to `1024 * availableProcessors`.
   **[V]**
3. The ~600 MB off-heap page cache described above.
4. Per-file indexing timestamps: `IndexingStamp.ourTimestampsCache`, bounded to
   100 entries (`index.timestamp.cache.size`, line 77 of `IndexingStamp.java`).
   **[V]**

A key lookup calls `MapIndexStorage.read(key, processor)` (line 307), which
pulls exactly one `ValueContainer` through the SLRU cache. A multi-key query
intersects posting lists one key at a time:
`FileBasedIndexEx.collectFileIdsContainingAllKeys` ->
`InvertedIndexUtil.collectInputIdsContainingAllKeys`
(`platform/indexing-impl/src/com/intellij/util/indexing/FileBasedIndexEx.java`
line 568). **[V]**

**Conclusion for question 1.** IntelliJ never materializes an index in heap. The
index is a pair of persistent maps on disk. Heap holds a small, fixed-size,
key-granular cache. There is no "build the whole thing, then answer queries"
step.

---

## 2. Incremental invalidation: the exact update path

### 2.1 VFS event to file update

`ChangedFilesCollector`
(`platform/lang-impl/src/com/intellij/util/indexing/events/ChangedFilesCollector.kt`)
is an async VFS listener. **[V]**

- `prepareChange(events)` returns a `ChangeApplier`. `afterVfsChange()` calls
  `ensureUpToDateAsync()`.
- `processFilesToUpdateInReadAction()` walks merged change records and, per
  file id, calls one of:
  - `fileBasedIndex.doTransientStateChangeForFile(fileId, file, ...)`
  - `fileBasedIndex.scheduleFileForIncrementalIndexing(fileId, file, true, ...)`
  - `fileBasedIndex.doInvalidateIndicesForFile(fileId, file, ...)`
- Each record is processed inside `IndexingStamp.flushCache(changeInfo.fileId)`.

`FileBasedIndexImpl.scheduleFileForIncrementalIndexing` (line 1940) **[V]**:

1. Reads `IndexingStamp.getNontrivialFileIndexedStates(fileId)`: the list of
   index IDs that hold data for this one file.
2. Removes transient (in-memory document) data for those indexes.
3. Applies content-independent indexes in place (`tryIndexWithoutContent`).
4. For everything else it calls
   `getIndex(indexId).invalidateIndexedStateForFile(fileId)` and then
   `getFilesToUpdateCollector().scheduleForUpdate(FileIndexingRequest.updateRequest(file), ...)`.

**Nothing global is cleared.** The scope of the operation is the set of index
IDs that had data for that single `fileId`.

### 2.2 Reindexing that one file

`FileBasedIndexImpl.doIndexFileContent` (line 1477) iterates the required
indexes for that file. For each one it calls `createSingleIndexValueApplier`,
which calls `index.mapInputAndPrepareUpdate(inputId, currentFC)` (line 1673).
**[V]**

`MapReduceIndex.prepareUpdate(inputId, inputData)` (line 292) builds an
`UpdateData` whose change iteration is **[V]**:

```java
InputDataDiffBuilder<Key, Value> diffBuilder = getKeysDiffBuilder(inputId);
Map<Key, Value> newData = inputData.getKeyValues();
return diffBuilder.differentiate(newData, changedEntriesProcessor);
```

`MapInputDataDiffBuilder.differentiate`
(`platform/util/src/com/intellij/util/indexing/impl/MapInputDataDiffBuilder.java`)
compares the old per-file map with the new one and emits only `added`,
`updated`, `removed` per key. **[V]**

`MapReduceIndex.changedEntriesProcessor` (line 375) turns each event into
exactly one inverted-map operation **[V]**:

```java
case ADDED:   myStorage.addValue(key, inputId, value);
case UPDATED: myStorage.updateValue(key, inputId, value);
case REMOVED: myStorage.removeAllValues(key, inputId);
```

Then, and only if there was a difference, `updateWith` calls
`updateData.updateForwardIndex()` (line 418), which writes the one new forward
entry for that `inputId`. **[V]**

Important detail for memory: the write does **not** load the posting list.
`MapIndexStorage.addValue` calls `myCache.read(key).addValue(inputId, value)`,
and `ChangeTrackingValueContainer`
(`platform/util/src/com/intellij/util/indexing/impl/ChangeTrackingValueContainer.java`)
records the change in `myAdded` / `myInvalidated` while `myMergedSnapshot`
stays `null`. On eviction `ValueContainerMap.merge` appends only the diff:
`myPersistentMap.appendData(key, out -> valueContainer.saveDiffTo(out, ...))`.
**[V]**

### 2.3 File deletion

`FileBasedIndexImpl.removeDataFromIndicesForFile(fileId, file, cause)`
(line 751) reads `IndexingStamp.getNontrivialFileIndexedStates(fileId)` and
calls `removeSingleIndexValue(indexId, fileId)` per index. **[V]** Again the
blast radius is one file id.

### 2.4 What is `IndexingStamp`

`platform/lang-impl/src/com/intellij/util/indexing/IndexingStamp.java`. Class
javadoc **[V]**:

> A file has three indexed states (per particular index): indexed (with
> particular index_stamp which monotonically increases), outdated and (trivial)
> unindexed.

It is a per-`(fileId, indexId)` `long`, persisted in VFS file attributes
(`IndexingStampStorageOverFastAttributes` /
`IndexingStampStorageOverRegularAttributes`, line 92). Constants: `-2` =
outdated, `0` = never indexed. Otherwise the value is
`IndexVersion.getIndexCreationStamp(indexName)` at the moment of indexing.
`isFileIndexedStateCurrent` returns up-to-date only when
`stamp == indexCreationStamp` (lines 46-62). **[V]**

Bumping an index's declared version therefore invalidates every file for that
one index at once, without touching any other index. `FileBasedIndexImpl.clearIndex`
(line 985) does `advanceIndexVersion(indexId); getIndex(indexId).clear();`. **[V]**

`IndexingStamp` has a documented weakness, and IntelliJ pairs it with a second
signal. `IndexingFlag`
(`platform/lang-impl/src/com/intellij/util/indexing/IndexingFlag.kt`) stores,
per file in a VFS attribute, "file mod count + app indexing dependency stamp at
the moment the file was indexed". Its javadoc says it is the **fast** check and
`IndexingStamp` is the **per-index but slower** check, and that "in practice the
combination of the two should be used". `FileBasedIndexImpl.getIndexingState`
(line 2059) does exactly that: `IndexingFlag.isFileChanged(...) == YES` short
circuits to outdated, else it defers to `index.getIndexingStateForFile(fileId, file)`.
**[V]**

### 2.5 Is anything global rebuilt?

No, not on a file change. **[V]** The only whole-index rebuild triggers I found
are:
- `IndexVersion.versionDiffers` reporting `InitialBuild`, `VersionChanged`, or
  `CorruptedRebuild` (`IndexVersion.java` lines 124-141).
- `MapReduceIndex.requestRebuild(Throwable)` after a storage exception
  (`IndexStorageUpdate.update`, line 459).
- `AppIndexingDependenciesService.invalidateAllStamps` after "invalidate
  caches" (documented in `ProjectIndexingDependenciesService.kt` header).

---

## 3. Find usages and reference search

### 3.1 Candidate narrowing by identifier

`IdIndex`
(`platform/indexing-impl/src/com/intellij/psi/impl/cache/impl/id/IdIndex.java`)
class javadoc **[V]**:

> An implementation of identifier index where the key is an identifier hash,
> and the value is an occurrence mask (`UsageSearchContext`).

`IdIndexEntry` stores only the `int` hash of the word, not the word. Its javadoc
says so, and states the consequence explicitly **[V]**:

> That opens a possibility of collisions -- i.e. IdIndex lookup could return
> 'false positives' ... Which is fine, since we always re-check all the files
> found by IdIndex to really contain requested identifier.

The value is a bitmask of occurrence contexts (`UsageSearchContext`: code,
comment, string literal, plain text, foreign language). So per file the index
records: "identifier hash H occurs in this file, in these kinds of context".
That is a **purely per-file fact**. It contains no cross-file relation at all.

### 3.2 Query-time composition

`PsiSearchHelperImpl`
(`platform/indexing-impl/src/com/intellij/psi/impl/search/PsiSearchHelperImpl.java`):

1. `TextIndexQuery.fromWords(...)` (line 1446) splits the target name into
   words and maps each to an `IdIndexEntry`. **[V]**
2. `TextIndexQuery.toFileBasedIndexQueries()` (line 1416) returns an
   `AllKeysQuery<>(IdIndex.NAME, myIdIndexEntries, contextCondition)`. **[V]**
3. `collectFiles` (line 1116) runs
   `processFilesContainingAllKeys(...)` to get the candidate `VirtualFile`s,
   then re-reads the per-file occurrence mask with
   `FileBasedIndex.getInstance().processValues(IdIndex.NAME, indexEntry, file, ...)`
   and intersects the masks with `oldMask & maskRef.get()`. **[V]**
4. It buckets candidates by priority: `targetFiles`, `nearDirectoryFiles`,
   `containerNameFiles`, `restFiles` (line 1116 signature). This is a locality
   heuristic, not an index.
5. `processVirtualFile` (line 600) then loads PSI for each candidate under a
   read action and runs the per-file text scan.
6. `adaptProcessor` (line 1184) calls
   `LowLevelSearchUtil.processElementsAtOffsets(...)`, which walks to the PSI
   element at each text offset.

### 3.3 The resolve check

`SingleTargetRequestResultProcessor`
(`platform/indexing-api/src/com/intellij/psi/search/SingleTargetRequestResultProcessor.java`),
whole class **[V]**:

```java
List<PsiReference> references = myService.getReferences(element, hints);
for (PsiReference ref : references) {
  if (ReferenceRange.containsOffsetInElement(ref, offsetInElement)
      && ref.isReferenceTo(myTarget) && !consumer.process(ref)) return false;
}
```

So the pipeline is: **hash-level index narrowing -> text re-check -> PSI resolve
per candidate occurrence**. The index never claims a usage. It only claims a
name might occur.

### 3.4 ResolveCache

`platform/core-impl/src/com/intellij/psi/impl/source/resolve/ResolveCache.java`
**[V]**:

- 8 maps in an `AtomicReferenceArray`, indexed by
  `(isPhysical, incompleteCode, isPoly)` (line 30).
- Each map is a `ConcurrentWeakKeySoftValueHashMap` (line 87). Keys are the
  `PsiReference` objects (weak). Values are soft.
- Invalidation is coarse and total:
  ```java
  bus.connect().subscribe(PsiManagerImpl.ANY_PSI_CHANGE_TOPIC, new AnyPsiChangeListener() {
    @Override public void beforePsiChanged(boolean isPhysical) { clearCache(isPhysical); }
  });
  ```
  `clearCache` nulls the map slots (lines 128-136). Physical change clears all
  8; non-physical clears the last 4.
- `LowMemoryWatcher.register(() -> onLowMemory(), this)` clears everything under
  memory pressure (line 38).

**Correction to a common belief.** In this revision there is no separate
"out-of-code-block modification count" for cache invalidation.
`platform/core-api/src/com/intellij/psi/util/PsiModificationTracker.java`
line 88 **[V]**:

```java
@Deprecated @ApiStatus.ScheduledForRemoval Key JAVA_STRUCTURE_MODIFICATION_COUNT = MODIFICATION_COUNT;
```

The javadoc for `MODIFICATION_COUNT` says a cached value with that dependency
becomes outdated on "literally every PSI change", and it recommends
`forLanguage(Language)` as the finer-grained alternative. So the modern design
is: one very coarse counter, plus per-language counters
(`PsiModificationTrackerImpl.myLanguageTrackers`, a weak map of
`SimpleModificationTracker`). **[V]**

### 3.5 Where do cross-file relations live?

Almost nowhere. The reference example is Java direct inheritors.

`java/java-indexing-impl/src/com/intellij/psi/impl/search/JavaDirectInheritorsSearcher.java`,
`calculateDirectSubClasses` (line 199) **[V]**:

```java
Collection<PsiReferenceList> candidates = dumbService.runReadActionInSmartMode(
    () -> JavaSuperClassNameOccurenceIndex.getInstance().getOccurrences(baseClassName, project, globalUseScope));
RelaxedDirectInheritorChecker checker = ...;
...
if (parent instanceof PsiClass && checker.checkInheritance(candidate = (PsiClass)parent)) { ... }
```

`JavaSuperClassNameOccurenceIndex`
(`java/java-indexing-impl/src/com/intellij/psi/impl/java/stubs/index/JavaSuperClassNameOccurenceIndex.java`)
is a stub index on `JavaStubIndexKeys.SUPER_CLASSES`. Its per-file fact is
"this file has an extends/implements list that mentions the **short name** X".
The actual inheritance edge is decided at query time by `checkInheritance`.
**[V]**

The result is cached in a weak/soft map, not persisted:
`java/java-indexing-impl/src/com/intellij/psi/impl/search/HighlightingCaches.java`
**[V]**:

```java
final ConcurrentMap<PsiClass, PsiClass[]> DIRECT_SUB_CLASSES = createWeakCache();
final ConcurrentMap<PsiClass, Iterable<PsiClass>> ALL_SUB_CLASSES = createWeakCache();
final Map<PsiMethod, Iterable<PsiMethod>> OVERRIDING_METHODS = createWeakCache();
```
```java
public void beforePsiChanged(boolean isPhysical) { if (isPhysical) allCaches.forEach(Map::clear); }
```

**The one materialized cross-file index.** `CompilerReferenceService`
(`java/java-indexing-impl/src/com/intellij/compiler/CompilerReferenceService.java`)
is a real backward-reference index, but it is built by the **compiler**, not by
the IDE indexer, and it is used only as a scope narrower. Its javadoc **[V]**:

> The service is intended to provide an information about class/method/field
> usages or classes hierarchy that is obtained on compilation time. It means
> that this service should not affect any find usages result when initial
> project is not compiled ... Any result provided by this service should be
> valid even if some part of a given project was modified after compilation.

Correctness after edits comes from `DirtyScopeHolder`
(`java/compiler/impl/src/com/intellij/compiler/backwardRefs/DirtyScopeHolder.java`),
which tracks modules changed since the last compilation. `JavaDirectInheritorsSearcher`
intersects with `info.getDirtyScope()` (line 209) and falls back to the normal
index-plus-resolve search inside that dirty scope. **[V]**

This is the important architectural lesson: when IntelliJ does materialize a
cross-file graph, it pairs it with an explicit **dirty scope** so that a stale
region degrades to the derived path instead of forcing a rebuild.

---

## 4. Stub indexes

### 4.1 What a stub is

A stub is a serialized, per-file skeleton of declarations. It carries the
information needed to answer "what is declared here and with what shape",
without the full AST and without the file text.

`StubUpdatingIndex`
(`platform/indexing-impl/src/com/intellij/psi/stubs/StubUpdatingIndex.java`)
is a `SingleEntryFileBasedIndexExtension<SerializedStubTree>`: one value per
file, keyed by the file id. **[V]** Its indexer:

```java
Stub stub = StubTreeBuilder.buildStubTree(inputData, type);
...
serializedStubTree = SerializedStubTree.serializeStub(stub, mySerializationManager, myStubIndexesExternalizer);
```

`getVersion()` returns `45 + (compression ? 1 : 0)` and `enableWal()` is true.
**[V]**

### 4.2 Two levels

There are two distinct things:

1. **The stub tree index** (`ID = "Stubs"`): `fileId -> SerializedStubTree`.
   This is one ordinary `MapReduceIndex` with a forward index.
2. **The stub indexes** (`StubIndexKey`, for example
   `JavaStubIndexKeys.SUPER_CLASSES`, class-name indexes, method-name indexes):
   `Key -> Set<fileId>`. These are `UpdatableIndex<K, Void, ...>`, that is,
   inverted maps with a `Void` value.

The second level is derived from the first at update time, not at index time.
`StubCumulativeInputDiffBuilder.updateStubIndices`
(`platform/indexing-impl/src/com/intellij/psi/stubs/StubCumulativeInputDiffBuilder.java`)
**[V]**:

```java
Map<StubIndexKey<?, ?>, Map<Object, StubIdList>> oldForwardIndex =
   myCurrentTree == null ? Collections.emptyMap() : myCurrentTree.getStubIndicesValueMap();
Map<StubIndexKey<?, ?>, Map<Object, StubIdList>> newForwardIndex =
   newTree == null ? Collections.emptyMap() : newTree.getStubIndicesValueMap();
Collection<StubIndexKey<?, ?>> affectedIndexes =
   ContainerUtil.union(oldForwardIndex.keySet(), newForwardIndex.keySet());
for (StubIndexKey key : affectedIndexes) {
  Set<Object> oldKeys = oldForwardIndex.getOrDefault(key, emptyMap()).keySet();
  Set<Object> newKeys = newForwardIndex.getOrDefault(key, emptyMap()).keySet();
  stubIndex.updateIndex(key, myInputId, oldKeys, newKeys);
}
```

`StubIndexEx.updateIndex`
(`platform/indexing-impl/src/com/intellij/psi/stubs/StubIndexEx.java` line 74)
emits `removed(oldKey, fileId)` for keys only in old and `added(newKey, null,
fileId)` for keys only in new. **[V]** So a stub index is a set difference of
two per-file key sets. The serialized stub tree **is** the forward index for
every stub index at once.

There is also a cheap no-op path: if the new serialized tree hashes and
compares equal to the old one, `differentiate` returns `false` immediately and
no stub index is touched. **[V]** (`treesAreEqual`, line 96.)

### 4.3 Answering a declaration query without parsing

`StubIndexEx.processElements` (line 130) **[V]**:

1. `IntSet fileIds = getContainingIds(indexKey, key, project, idFilter, scope);`
2. For each file, retrieve the `StubIdList` (the positions of matching stubs
   inside that file's stub tree), memoized in
   `myCachedStubIds`, a `CachedValue` whose dependency is the stub updating
   index modification stamp (lines 60-64).
3. `myStubProcessingHelper.processStubsInFile(project, file, list, ...)`
   materializes PSI for just those stubs.

Step 3 does not need the parser: `PsiFileImpl` can be backed by the stub tree
alone (`getGreenStubTree`, `derefStub`). AST is parsed only if something asks
for detail the stub does not carry. **[I]** for the exact trigger boundary; the
soft/weak holding is **[V]** (see 6.3).

---

## 5. Readiness model

### 5.1 Dumb mode is the default, and it throws

The default query behavior during indexing is **not** blocking. It is failure.
`FileBasedIndexImpl.ensureUpToDate` (line 845) **[V]**:

```java
if (ActionUtil.isDumbMode(project) && getCurrentDumbModeAccessType_NoDumbChecks() == null) {
  handleDumbMode(project);   // throws IndexNotReadyException
}
```

Blocking is the **caller's opt-in**:
- `DumbService.waitForSmartMode()` /
  `DumbService.waitForSmartMode(timeoutMillis)`
  (`platform/core-api/src/com/intellij/openapi/project/DumbService.kt` lines
  110, 118). **[V]**
- `DumbService.runReadActionInSmartMode(r)` (line 198), now deprecated in favour
  of `smartReadAction` and `NonBlockingReadAction.inSmartMode`. Note its
  documented trap: "This method does not have any effect if it is called inside
  another read action" and it then "pretends it's already smart and fails with
  IndexNotReadyException". **[V]**

Degraded results are also an opt-in, with two explicit levels.
`platform/indexing-api/src/com/intellij/util/indexing/DumbModeAccessType.java`
**[V]**:

- `RELIABLE_DATA_ONLY`: "only up-to-date indexed data will be returned".
- `RAW_INDEX_DATA_ACCEPTABLE`: "any (even invalid) data currently present in the
  index will be returned". Explicitly not allowed for `StubIndex`
  (`StubIndexEx.processElements` throws `AssertionError` for it, line 161).

Probing readiness is `DumbService.isDumb`.

### 5.2 Small change sets never enter dumb mode

`FileBasedIndexExtension` class javadoc **[V]**:

> Every index will be updated when some files matched to
> `FileBasedIndexExtension#getInputFilter()` are changed. If the changed file
> count is relatively small, it will be done lazily on the first index access.
> Otherwise an `DumbModeTask` will be queued to `DumbService`.

The lazy path is `FileBasedIndexImpl.forceUpdate` (line 1804), called from
`ensureUpToDate`. It drains `myFilesToUpdateCollector` filtered to the current
project and reindexes those files inline, on the querying thread. **[V]** The
threshold for the async path is in `ChangedFilesCollector.ensureUpToDateAsync`:
`if (eventMerger.approximateChangesCount < 20 || ...) return`. **[V]**

**This is the exact behavior the Bifrost owner asked for**, and IntelliJ gets it
without blocking on a global build, because "catch up" means "reindex the N
changed files", not "rebuild the index".

### 5.3 Startup scanning

`ProjectIndexingDependenciesService`
(`platform/lang-impl/src/com/intellij/util/indexing/dependencies/ProjectIndexingDependenciesService.kt`)
class javadoc **[V]**:

> There are two kinds of tokens: scanning and indexing. Scanning tokens must be
> explicitly marked as "successfully completed". If there are incomplete or
> unsuccessful scanning tokens remaining on IDE shutdown, then IDE will do
> "heavy" scanning on the following start.

And:

> If VFS is invalidated, we don't need any additional actions. IndexingFlag is
> stored in the VFS records, invalidating VFS effectively means "reset all the
> stamps to the default value (unindexed)".

Two persisted carry-overs across sessions:
1. `IndexingFlag` and `IndexingStamp` live in VFS file attributes, so they
   survive restart. **[V]**
2. Files that were dirty when the IDE closed are persisted:
   `FileBasedIndexImpl.persistDirtyFiles` writes a `ProjectDirtyFilesQueue`
   (line 626); `registerProject(project, projectDirtyFileIdsFromLastSession)`
   (line 358) restores it. **[V]**

### 5.4 Per-file up-to-date check

`UnindexedFilesFinder.evaluateFileStatus`
(`platform/lang-impl/src/com/intellij/util/indexing/UnindexedFilesFinder.java`
line 183) **[V]**:

```java
FileIndexingStamp indexingStamp = indexingRequest.getFileIndexingStamp(file);
...
if (IndexingFlag.isFileIndexed(file, indexingStamp)) {
  return new UnindexedFileStatusBuilder(applicationMode);   // fast exit, no read action
}
```

The fast path is one attribute read per file, taken **before** entering a read
action and before touching PSI, file type, or content. Only on a miss does it
consult `IndexingStamp.getNontrivialFileIndexedStates(inputId)` and the per-index
`getIndexingStateForFile`. **[V]** That is how a scan of a million-file project
stays affordable: the common case is a compare of two longs.

---

## 6. Memory bounding

### 6.1 Bounded caches over persistent maps

| Cache | Bound | Citation |
|---|---|---|
| Inverted-map key cache | SLRU, protected = `cacheSize`, probation = `cacheSize/4`; default 1024 keys per index | `MapIndexStorageCache.kt` `SlruCache`; `FileBasedIndexExtension.DEFAULT_CACHE_SIZE` |
| `IdIndex` key cache | `64 * 1024` keys | `IdIndex.getCacheSize()` |
| Stub tree cache | `1024 * availableProcessors` | `StubUpdatingIndex.getCacheSize()` |
| PHM append buffer | SLRU 16384 / 4096 | `PersistentMapImpl.createAppendCache` line 270 |
| Page cache (all storages) | ~600 MB **direct/off-heap** | `PageCacheUtils.FILE_PAGE_CACHES_TOTAL_CAPACITY_BYTES` |
| `IndexingStamp` timestamps | 100 files | `IndexingStamp.INDEXING_STAMP_CACHE_CAPACITY` |
| `ResolveCache` | weak keys, soft values, 8 maps | `ResolveCache.createWeakMap` |
| `HighlightingCaches` (inheritors, overriders) | weak keys, soft values | `HighlightingCaches.createWeakCache` |

All of them are **[V]**.

### 6.2 Memory-pressure hooks

`LowMemoryWatcher` is registered in at least three of the above:
`MapReduceIndex` (line 101, calls `clearCaches()` then `flush()`),
`PersistentMapImpl` (line 205, drops the append cache), and `ResolveCache`
(line 38). **[V]**

### 6.3 What they deliberately do not keep in heap

- The posting lists. `ChangeTrackingValueContainer` writes deltas without ever
  loading `myMergedSnapshot`. **[V]**
- The identifier strings. `IdIndexEntry` stores only an `int` hash and accepts
  false positives, which the resolve step filters. **[V]**
- The AST. `PsiFileImpl.createTreeElementPointer`
  (`platform/core-impl/src/com/intellij/psi/impl/source/PsiFileImpl.java` line
  815) returns a `SoftReference<FileElement>`, or a `PatchedWeakReference` in
  batch mode. **[V]**
- The stub trees in PSI. `FileTrees.myStub` is a `Reference<StubTree>` wrapped
  in a `SoftReference`
  (`platform/core-impl/src/com/intellij/psi/impl/source/FileTrees.java` lines
  33, 147). **[V]**
- The inheritance graph, the override graph, and the reference graph. See
  section 3.5. **[V]**

The rule that emerges: **anything that grows with workspace size is on disk;
anything in heap is either bounded by a constant or is soft/weak.**

---

## 7. Synthesis for Bifrost

### 7.1 The problem restated in IntelliJ's terms

`RustUsageIndex`
(`crates/bifrost-analysis/src/analyzer/rust/usage_index.rs` lines 472-494) is a
single struct holding 17 workspace-wide `HashMap`s: `exports_by_file`,
`importer_reverse`, `declaration_domains`, `identities_by_name`,
`module_importers`, `declaration_identities`, `value_constructor_identities`,
`module_domains`, `module_extents`, `physical_roots`, `actual_crate_roots`,
`physical_owners`, `origin_routes_by_file`, `macro_visible_ranges`,
`module_aliases`, `module_files`. **[V]**

It is cached behind `usage_index: Arc<PoolSafeMemo<RustUsageIndex>>`
(`crates/bifrost-analysis/src/analyzer/rust/mod.rs` line 86) and `update()` and
`update_all()` both replace it with `Arc::new(PoolSafeMemo::new())` (lines 634
and 660). **[V]** That is: any file change drops the whole thing.

In IntelliJ terms, `RustUsageIndex` fuses three things that IntelliJ keeps
separate:
1. Per-file forward facts (exports, imports, module extents, identities).
2. Inverted name indexes (`identities_by_name`, `module_importers`).
3. Derived cross-file relations (`importer_reverse`, alias routes,
   `physical_owners`).

Levels 1 and 2 are the only ones IntelliJ persists. Level 3 it computes at query
time and holds in a soft cache.

### 7.2 What Bifrost already has

Bifrost's SQLite store is closer to the IntelliJ shape than it might look.
`crates/bifrost-core/migrations/cache/0001-current-baseline.sql`: **[V]**

- `blobs(blob_oid, lang, generation)` is the unit of storage, keyed by content
  hash. Everything cascades from it with `ON DELETE CASCADE`.
- `code_units(blob_oid, lang, unit_key, ..., short_name, identifier,
  exact_fqn, normalized_fqn, ...)` is the per-file declaration table. This is
  the stub-tree analogue.
- `idx_code_units_lang_short_name ON code_units(lang, short_name)` is already an
  inverted **name -> blob** index. This is the `IdIndex` analogue, at
  declaration granularity.
- `import_statements(blob_oid, lang, ordinal, statement)` and
  `import_details(blob_oid, lang, ordinal, info BLOB)` already persist per-file
  import facts.
- `path_symbol_units(lang, rel_path, blob_oid, kind, package_name, short_name,
  exact_fqn, normalized_fqn)` from migration 0002 is a path-keyed projection
  with `generation` added in 0004.

Content-hash keying gives Bifrost something IntelliJ pays for with
`IndexingStamp` and `IndexingFlag`: **the up-to-date check is free**. If the
blob oid of a file is unchanged, its rows are correct by construction. If it
changed, its rows are a different primary key and the old rows are simply
orphaned until GC. There is no diff to compute and no delete to perform on the
common path.

`Liveness` (`crates/bifrost-analysis/src/analyzer/store/liveness.rs`) already
resolves `ProjectFile -> Oid`, with a batched startup path
(`oids_for_files`) and a point path (`oid_for_path`) documented as "reserved for
small watcher updates". **[V]** That is the `UnindexedFilesFinder` fast-path
analogue.

### 7.3 Per-file vs genuinely cross-file

I classified each `RustUsageIndex` product. **[I]** for the classification;
**[V]** for the field list.

| Product | Per-file? | Argument |
|---|---|---|
| `exports_by_file` | **Yes** | An `ExportIndex` is built from one file's `pub use` / `pub mod` items. |
| `origin_routes_by_file` | **Yes** | Keyed by file, derived from that file's import statements. |
| `module_extents`, `physical_roots` | **Yes** | Byte ranges and module identity of one file. |
| `declaration_identities`, `value_constructor_identities` | **Yes** | A `CodeUnit -> identity` map for units of one file. |
| `macro_visible_ranges` | **Yes** | Lexical ranges inside one file. |
| `identities_by_name` | **Inverted, derivable** | This is exactly `code_units(lang, short_name)`. It is not a graph; it is a per-file fact plus a SQL index. |
| `module_importers` | **Inverted, derivable** | "Which files import module M" is `SELECT blob_oid FROM rust_import_targets WHERE module = M`. Per-file fact plus an index. |
| `importer_reverse` | **Inverted, derivable** | Same shape as above; the comment at line 480 already says it is derived from `importer_reverse`. |
| `module_files`, `module_aliases`, `physical_owners` | **Cross-file** | Resolving `mod foo;` to `foo.rs` or `foo/mod.rs` needs the file set. Alias routes chain through other files. |
| Export **chains** (transitive re-export) | **Cross-file** | `pub use a::b` where `a` also re-exports needs a walk. |
| `actual_crate_roots` | **Cross-file, but tiny** | One row per crate; Cargo metadata already bounds it. |

The important observation: only the last group is genuinely cross-file, and
even there the shape is a **bounded walk from a starting point**, not a
materialized closure. IntelliJ's answer for exactly this shape is
`JavaDirectInheritorsSearcher`: query the inverted index for candidates by
name, then verify each candidate by resolving, then cache the answer in a soft
map keyed by the query, invalidated by a modification counter.

### 7.4 The invalidation story

With content-hash keys the story is short.

**On a single-file change (path P, old blob A, new blob B):**

Rows deleted: none on the hot path. The change is
`INSERT OR IGNORE INTO blobs(B, lang, gen)` plus inserts into the per-blob
tables. The old blob A's rows become unreachable from the live file set and are
removed by the existing GC (`crates/bifrost-analysis/src/analyzer/store/gc.rs`).

Rows updated: `path_symbol_units` for `rel_path = P` (it is path-keyed, so it
must be rewritten), and the in-memory `ProjectFile -> Oid` map in `Liveness`.

Caches invalidated: only entries whose key mentions P or a name that P
contributes. Concretely, a `resolve_cache` keyed by
`(reference site, name)` should be dropped wholesale on any change, in the same
spirit as `ResolveCache.clearCache`. That is cheap because it is a bounded
in-memory map, not a workspace index.

Rebuilt: nothing.

**Queries that recompute:** export-chain walks, module-file resolution, and
alias routes. They recompute from persisted per-file facts, per query, with
memoization behind a modification counter.

### 7.5 Proposed shape for Bifrost Rust usage v2

**Storage (SQLite, all keyed by `blob_oid`, all `ON DELETE CASCADE` from
`blobs`).** Five new per-file fact tables, each written by the same pass that
already writes `code_units`:

```sql
CREATE TABLE rust_exports(       -- pub use / pub mod, one row per exported name
  blob_oid TEXT, lang TEXT, ordinal INTEGER,
  exported_name TEXT NOT NULL,   -- the name visible to importers
  source_path   TEXT NOT NULL,   -- the path it re-exports, verbatim, unresolved
  is_glob INTEGER NOT NULL,
  PRIMARY KEY(blob_oid, lang, ordinal)) WITHOUT ROWID, STRICT;
CREATE INDEX idx_rust_exports_name ON rust_exports(exported_name);

CREATE TABLE rust_import_targets( -- one row per (file, module it imports)
  blob_oid TEXT, lang TEXT, ordinal INTEGER,
  module_path TEXT NOT NULL,      -- unresolved, as written
  bound_name  TEXT,               -- NULL for glob
  PRIMARY KEY(blob_oid, lang, ordinal)) WITHOUT ROWID, STRICT;
CREATE INDEX idx_rust_import_targets_module ON rust_import_targets(module_path);
CREATE INDEX idx_rust_import_targets_bound  ON rust_import_targets(bound_name);

CREATE TABLE rust_modules(        -- inline and file modules declared in this file
  blob_oid TEXT, lang TEXT, ordinal INTEGER,
  module_name TEXT NOT NULL, is_inline INTEGER NOT NULL,
  start_byte INTEGER NOT NULL, end_byte INTEGER NOT NULL,
  PRIMARY KEY(blob_oid, lang, ordinal)) WITHOUT ROWID, STRICT;

CREATE TABLE rust_identifier_occurrences(  -- the IdIndex analogue
  blob_oid TEXT, lang TEXT,
  identifier TEXT NOT NULL,
  context_mask INTEGER NOT NULL,  -- code / comment / string / macro
  PRIMARY KEY(blob_oid, lang, identifier)) WITHOUT ROWID, STRICT;
CREATE INDEX idx_rust_ident_occ ON rust_identifier_occurrences(lang, identifier);
```

The last table is the load-bearing one and the piece Bifrost does not have
today. It is what turns "find usages of `foo`" from "consult a global graph"
into "`SELECT blob_oid ... WHERE identifier = 'foo'`, then verify each
candidate". Note that IntelliJ stores a **hash** and accepts collisions; Bifrost
can store the string, because SQLite already dictionary-compresses nothing but
the row count is bounded by distinct identifiers per file.

**Query-time composition.** Replace `RustUsageIndex` with a stateless
`RustUsageQueries<'a>` that borrows the store and a small bounded cache:

```
fn files_referencing(name) -> Vec<ProjectFile>
    = SELECT blob_oid FROM rust_identifier_occurrences WHERE identifier = ?
      -> map blob -> live ProjectFile via Liveness
      -> filter by context_mask
fn importers_of(module) -> Vec<ProjectFile>
    = SELECT blob_oid FROM rust_import_targets WHERE module_path = ?
fn export_chain(name) -> ...
    = seed from rust_exports WHERE exported_name = ?, then walk,
      bounded depth, memoized
```

**Bounded caches, nothing workspace-sized.** Three caches, all with an explicit
capacity, all keyed by a `(generation, query)` pair so a store generation bump
invalidates them for free:

1. `module_resolution: LruCache<(ProjectFile, ModuleName), Option<ProjectFile>>`
   -- the `physical_owners` / `module_files` replacement.
2. `export_chain: LruCache<ExportSeed, Vec<Resolution>>` -- memoized walk.
3. `resolve: LruCache<(ProjectFile, offset), Resolution>` -- the `ResolveCache`
   analogue. Cleared on any file change, exactly like
   `ResolveCache.clearCache(true)`.

Give each a byte budget through the existing `build_weighted_cache` mechanism
already used for `imported_code_units` and friends in
`crates/bifrost-analysis/src/analyzer/rust/mod.rs`.

**Readiness.** The owner wants block-until-ready as the default. IntelliJ's
default is the opposite (throw `IndexNotReadyException`), but the reason is that
IntelliJ's "not ready" can last minutes. Under this design Bifrost's "not ready"
means "N changed files have not been re-parsed", where N is small. So:

- Default: block. Bring the changed-file set up to date inline, on the querying
  thread, like `FileBasedIndexImpl.forceUpdate`.
- Add a threshold, like `ChangedFilesCollector.ensureUpToDateAsync`'s `< 20`:
  above it, hand the batch to a background pass and expose a readiness probe.
- Provide the probe (`usage_index_ready()`), the analogue of `DumbService.isDumb`.

**What is gained.** No `warm_usage_index`. No minutes-long build. No 10.8 GB
RSS. A single-file change costs one re-parse plus a handful of row inserts. The
first query after a change costs one or two indexed SQLite lookups plus a
bounded verification walk over the candidates the lookup returned.

**What is risked, honestly.** Query latency moves from "one HashMap probe" to
"one SQLite lookup plus per-candidate verification". IntelliJ pays this cost too
and mitigates it with candidate bucketing by locality
(`PsiSearchHelperImpl.collectFiles`: target files, near-directory files,
container-name files, rest) and with an early-out `Processor` protocol. Bifrost
should copy both. The measurable risk is a name with thousands of occurrences.
That is the case to benchmark first, and IntelliJ's answer there is also the
one Bifrost should adopt: narrow the scope before you widen the search.
